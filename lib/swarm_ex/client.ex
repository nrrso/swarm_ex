defmodule SwarmEx.Client do
  @moduledoc """
  Main supervisor and coordinator for agent networks. Manages agent lifecycles,
  message passing, and error recovery.

  Provides:
  - Agent lifecycle management
  - Message routing and delivery
  - Context variable management
  - Handoff coordination
  - State inspection and health metrics
  - Rate limiting and timeout handling
  """

  use GenServer
  require Logger

  alias SwarmEx.Error
  alias SwarmEx.Telemetry

  @default_timeout 5_000
  # messages per second
  @default_rate_limit 100

  @type network_id :: String.t()
  @type agent_id :: String.t()
  @type correlation_id :: String.t()
  @type handoff_record :: %{
          from: agent_id(),
          to: agent_id(),
          timestamp: DateTime.t(),
          context_snapshot: map(),
          success: boolean()
        }

  @type t :: %__MODULE__{
          context: map(),
          active_agents: %{agent_id() => pid()},
          handoff_history: [handoff_record()],
          network_id: network_id(),
          correlation_id_counter: non_neg_integer(),
          started_at: integer(),
          rate_limiter: pid() | nil,
          stats: %{
            message_count: non_neg_integer(),
            error_count: non_neg_integer(),
            last_error_at: DateTime.t() | nil
          }
        }

  defstruct context: %{},
            active_agents: %{},
            handoff_history: [],
            network_id: nil,
            correlation_id_counter: 0,
            started_at: nil,
            rate_limiter: nil,
            stats: %{
              message_count: 0,
              error_count: 0,
              last_error_at: nil
            }

  # Client API

  @doc """
  Starts a new client process with the given options.

  ## Options
    * :name - Optional name for registration
    * :context - Initial context map
    * :rate_limit - Messages per second (default: #{@default_rate_limit})
    * :timeout - Default operation timeout (default: #{@default_timeout}ms)
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: opts[:name])
  end

  @doc """
  Sends a message to an agent in the network.
  Returns {:ok, response} on success or {:error, reason} on failure.
  """
  @spec send_message(GenServer.server(), term(), agent_id() | nil, keyword()) ::
          {:ok, term()} | {:error, term()}
  def send_message(pid, message, target_agent \\ nil, opts \\ []) do
    timeout = opts[:timeout] || @default_timeout
    GenServer.call(pid, {:send_message, message, target_agent, opts}, timeout)
  end

  @doc """
  Registers a new agent with the network.
  """
  @spec register_agent(GenServer.server(), agent_id(), pid()) :: :ok | {:error, term()}
  def register_agent(pid, agent_id, agent_pid) do
    GenServer.call(pid, {:register_agent, agent_id, agent_pid})
  end

  @doc """
  Updates the context with the given map of updates.
  """
  @spec update_context(GenServer.server(), map()) :: :ok | {:error, term()}
  def update_context(pid, updates) when is_map(updates) do
    GenServer.call(pid, {:update_context, updates})
  end

  @doc """
  Retrieves the current context or a specific key from it.
  """
  @spec get_context(GenServer.server(), term() | nil) :: {:ok, term()} | {:error, term()}
  def get_context(pid, key \\ nil) do
    GenServer.call(pid, {:get_context, key})
  end

  @doc """
  Initiates a handoff between two agents.
  """
  @spec handoff(GenServer.server(), agent_id(), agent_id()) :: :ok | {:error, term()}
  def handoff(pid, from_agent, to_agent) do
    GenServer.call(pid, {:handoff, from_agent, to_agent})
  end

  @doc """
  Gets an agent by ID from the network.
  """
  @spec get_agent(GenServer.server(), agent_id()) :: {:ok, pid()} | {:error, :agent_not_found}
  def get_agent(pid, agent_id) do
    GenServer.call(pid, {:get_agent, agent_id})
  end

  @doc """
  Returns network health metrics and statistics.
  """
  @spec get_network_stats(GenServer.server()) :: {:ok, map()} | {:error, term()}
  def get_network_stats(pid) do
    GenServer.call(pid, :get_stats)
  end

  @doc """
  Returns the current state of the network for inspection.
  Sensitive data is redacted.
  """
  @spec inspect_state(GenServer.server()) :: {:ok, map()} | {:error, term()}
  def inspect_state(pid) do
    GenServer.call(pid, :inspect_state)
  end

  # Server Callbacks

  @impl true
  def init(opts) do
    network_id = generate_network_id()
    start_time = System.monotonic_time()

    Logger.metadata(network_id: network_id)

    initial_state = %__MODULE__{
      network_id: network_id,
      context: opts[:context] || %{},
      started_at: start_time,
      rate_limiter: setup_rate_limiter(opts[:rate_limit] || @default_rate_limit)
    }

    Logger.info(%{
      event_type: "system_status",
      telemetry_event: "client_started",
      network_id: network_id,
      opts: redact_sensitive_opts(opts)
    })

    Telemetry.emit_network_creation(network_id, System.monotonic_time() - start_time)

    {:ok, initial_state}
  end

  @impl true
  def handle_call({:send_message, message, nil, opts}, from, state) do
    correlation_id = generate_correlation_id(state)
    Logger.metadata(correlation_id: correlation_id)

    Logger.debug(%{
      event_type: "message_flow",
      telemetry_event: "direct_message_received",
      message: inspect(message),
      from: inspect(from),
      correlation_id: correlation_id
    })

    new_state = update_stats(state, :message)
    {:reply, {:ok, message}, new_state}
  end

  @impl true
  def handle_call({:send_message, message, target_agent, opts}, _from, state) do
    correlation_id = generate_correlation_id(state)
    start_time = System.monotonic_time()

    Logger.metadata(correlation_id: correlation_id)

    case check_rate_limit(state.rate_limiter) do
      :ok ->
        with {:ok, agent_pid} <- get_agent_pid(target_agent, state),
             {:ok, response} <- forward_message_to_agent(agent_pid, message, opts) do
          duration = System.monotonic_time() - start_time

          Telemetry.emit_agent_message(
            target_agent,
            get_message_type(message),
            duration
          )

          new_state =
            state
            |> increment_correlation_id()
            |> update_stats(:message)

          {:reply, {:ok, response}, new_state}
        else
          {:error, reason} = error ->
            Logger.error(%{
              event_type: "operation_error",
              telemetry_event: "message_delivery_failed",
              target_agent: target_agent,
              reason: reason,
              correlation_id: correlation_id
            })

            new_state = update_stats(state, :error)
            {:reply, error, new_state}
        end

      {:error, wait_time} ->
        Logger.warning(%{
          event_type: "rate_limit",
          telemetry_event: "rate_limit_exceeded",
          wait_time: wait_time,
          correlation_id: correlation_id
        })

        {:reply, {:error, {:rate_limited, wait_time}}, state}
    end
  end

  @impl true
  def handle_call({:register_agent, agent_id, agent_pid}, _from, state) do
    if Map.has_key?(state.active_agents, agent_id) do
      Logger.error(%{
        event_type: "operation_error",
        telemetry_event: "agent_registration_failed",
        reason: :already_registered,
        agent_id: agent_id
      })

      {:reply, {:error, :already_registered}, state}
    else
      start_time = System.monotonic_time()
      Process.monitor(agent_pid)
      new_state = put_in(state.active_agents[agent_id], agent_pid)

      duration = System.monotonic_time() - start_time
      Telemetry.emit_agent_creation(agent_id, state.network_id, duration)

      Logger.info(%{
        event_type: "agent_lifecycle",
        telemetry_event: "agent_registered",
        agent_id: agent_id
      })

      {:reply, :ok, new_state}
    end
  end

  @impl true
  def handle_call({:update_context, updates}, _from, state) do
    start_time = System.monotonic_time()

    new_context = Map.merge(state.context, updates)
    new_state = %{state | context: new_context}

    Telemetry.emit_state_update(
      "context",
      map_size(new_context),
      System.monotonic_time() - start_time
    )

    {:reply, :ok, new_state}
  end

  @impl true
  def handle_call({:get_context, nil}, _from, state) do
    {:reply, {:ok, state.context}, state}
  end

  @impl true
  def handle_call({:get_context, key}, _from, state) do
    {:reply, {:ok, Map.get(state.context, key)}, state}
  end

  @impl true
  def handle_call({:handoff, from_agent, to_agent}, _from, state) do
    correlation_id = generate_correlation_id(state)
    start_time = System.monotonic_time()

    Logger.metadata(correlation_id: correlation_id)

    handoff_record = %{
      from: from_agent,
      to: to_agent,
      timestamp: DateTime.utc_now(),
      context_snapshot: state.context,
      success: false
    }

    with {:ok, source_pid} <- get_agent_pid(from_agent, state),
         {:ok, response} <- handle_agent_handoff(source_pid, to_agent) do
      duration = System.monotonic_time() - start_time

      successful_handoff = %{handoff_record | success: true}
      new_state = %{state | handoff_history: [successful_handoff | state.handoff_history]}

      Telemetry.emit_handoff(from_agent, to_agent, duration, true)

      {:reply, {:ok, response}, new_state}
    else
      {:error, reason} = error ->
        duration = System.monotonic_time() - start_time

        new_state = %{state | handoff_history: [handoff_record | state.handoff_history]}

        Telemetry.emit_handoff(from_agent, to_agent, duration, false)

        Logger.error(%{
          event_type: "operation_error",
          telemetry_event: "handoff_failed",
          from_agent: from_agent,
          to_agent: to_agent,
          reason: reason,
          correlation_id: correlation_id
        })

        {:reply, error, new_state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = %{
      active_agents: map_size(state.active_agents),
      handoff_count: length(state.handoff_history),
      successful_handoffs: Enum.count(state.handoff_history, & &1.success),
      context_size: map_size(state.context),
      uptime_ms: System.monotonic_time() - state.started_at,
      message_count: state.stats.message_count,
      error_count: state.stats.error_count,
      last_error_at: state.stats.last_error_at
    }

    {:reply, {:ok, stats}, state}
  end

  @impl true
  def handle_call(:inspect_state, _from, state) do
    redacted_state = %{
      state
      | context: redact_sensitive_data(state.context),
        handoff_history: Enum.map(state.handoff_history, &redact_sensitive_data/1)
    }

    {:reply, {:ok, redacted_state}, state}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, reason}, state) do
    {agent_id, active_agents} = remove_agent_by_pid(state.active_agents, pid)

    Telemetry.execute_event(
      [:agent, :terminate, :stop],
      %{system_time: System.system_time()},
      %{
        agent_id: agent_id,
        reason: reason,
        network_id: state.network_id
      }
    )

    Logger.warning(%{
      event_type: "agent_lifecycle",
      telemetry_event: "agent_terminated",
      agent_id: agent_id,
      reason: reason
    })

    new_state = %{state | active_agents: active_agents}
    {:noreply, new_state}
  end

  # Private Functions

  defp generate_network_id, do: "network_" <> UUID.uuid4(:hex)

  defp generate_correlation_id(state) do
    "#{state.network_id}_#{state.correlation_id_counter}"
  end

  defp increment_correlation_id(state) do
    %{state | correlation_id_counter: state.correlation_id_counter + 1}
  end

  defp get_agent_pid(agent_id, state) do
    case Map.fetch(state.active_agents, agent_id) do
      {:ok, pid} when is_pid(pid) ->
        if Process.alive?(pid) do
          {:ok, pid}
        else
          # Clean up dead reference
          {:error, {:agent_terminated, agent_id}}
        end

      {:ok, _dead_pid} ->
        # Clean up dead reference
        {:error, {:agent_terminated, agent_id}}

      :error ->
        {:error, {:agent_not_found, agent_id}}
    end
  end

  defp forward_message_to_agent(agent_pid, message, opts) do
    timeout = opts[:timeout] || @default_timeout

    try do
      GenServer.call(agent_pid, {:handle_message, message}, timeout)
    catch
      :exit, {:timeout, _} ->
        raise Error.AgentError,
          agent: agent_pid,
          reason: :timeout,
          context: %{
            message: message,
            timeout: timeout
          }

      :exit, reason ->
        raise Error.AgentError,
          agent: agent_pid,
          reason: reason,
          context: %{
            message: message,
            error_type: :communication_failed
          }
    end
  end

  defp handle_agent_handoff(source_pid, target_agent) do
    try do
      GenServer.call(source_pid, {:handoff, target_agent})
    catch
      :exit, reason ->
        raise Error.HandoffError,
          source_agent: source_pid,
          target_agent: target_agent,
          context: %{reason: reason}
    end
  end

  defp remove_agent_by_pid(active_agents, pid) do
    case Enum.find(active_agents, fn {_, agent_pid} -> agent_pid == pid end) do
      {agent_id, _} ->
        {agent_id, Map.delete(active_agents, agent_id)}

      nil ->
        raise Error.AgentError,
          agent: pid,
          reason: :not_found,
          context: %{operation: :remove_agent}
    end
  end

  defp setup_rate_limiter(limit_per_second) do
    {:ok, limiter} =
      SwarmEx.RateLimiter.start_link(
        rate_limit: limit_per_second,
        name: :"#{generate_network_id()}_rate_limiter"
      )

    limiter
  end

  defp check_rate_limit(limiter) when is_pid(limiter) do
    SwarmEx.RateLimiter.check_limit(limiter)
  end

  defp check_rate_limit(_), do: :ok

  defp get_message_type(message) when is_binary(message), do: :text
  defp get_message_type(%{type: type}), do: type
  defp get_message_type(message) when is_map(message), do: :structured
  defp get_message_type(_), do: :unknown

  defp update_stats(state, :message) do
    put_in(state.stats.message_count, state.stats.message_count + 1)
  end

  defp update_stats(state, :error) do
    %{
      state
      | stats: %{
          state.stats
          | error_count: state.stats.error_count + 1,
            last_error_at: DateTime.utc_now()
        }
    }
  end

  defp redact_sensitive_data(data) when is_map(data) do
    data
    |> Map.drop([:password, :token, :api_key, :secret])
    |> Map.new(fn
      {k, v} when is_map(v) -> {k, redact_sensitive_data(v)}
      {k, v} when is_list(v) -> {k, Enum.map(v, &redact_sensitive_data/1)}
      kv -> kv
    end)
  end

  defp redact_sensitive_data(data) when is_list(data) do
    Enum.map(data, &redact_sensitive_data/1)
  end

  defp redact_sensitive_data(data), do: data

  defp redact_sensitive_opts(opts) do
    opts
    |> Keyword.drop([:password, :token, :api_key, :secret])
    |> Keyword.new(fn
      {k, v} when is_map(v) -> {k, redact_sensitive_data(v)}
      {k, v} when is_list(v) -> {k, Enum.map(v, &redact_sensitive_data/1)}
      kv -> kv
    end)
  end
end
