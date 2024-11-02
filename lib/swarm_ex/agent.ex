defmodule SwarmEx.Agent do
  @moduledoc """
  Defines the behavior and implementation for SwarmEx agents.

  Each agent in the SwarmEx system is a process that can:
  - Process messages from other agents or clients
  - Maintain internal state
  - Participate in agent networks
  - Execute functions from tool modules
  - Perform self-health checks and recovery
  """

  require Logger
  alias SwarmEx.{Error, Telemetry, Utils}

  @typedoc "Basic agent state"
  @type state :: term()

  @typedoc "Message that can be processed by an agent"
  @type message :: term()

  @typedoc "Error response tuple"
  @type error :: {:error, term()}

  @typedoc "Response from message handling"
  @type response :: {:ok, term(), state()} | {:error, term()}

  @typedoc "Health status of an agent"
  @type health_status :: :healthy | :degraded | :unhealthy

  @typedoc "Agent configuration options"
  @type agent_opts :: %{
          optional(:name) => String.t(),
          optional(:instruction) => String.t(),
          optional(:network_id) => String.t(),
          optional(:network_pid) => pid(),
          optional(:health_check_interval) => non_neg_integer(),
          optional(:recovery_max_retries) => non_neg_integer(),
          optional(:recovery_backoff_ms) => non_neg_integer(),
          optional(atom()) => term()
        }

  @typedoc "Agent state map"
  @type agent_state :: %{
          name: String.t() | nil,
          instruction: String.t() | nil,
          network_id: String.t() | nil,
          network_pid: pid() | nil,
          custom_opts: keyword(),
          started_at: DateTime.t(),
          health_status: health_status(),
          health_check_interval: non_neg_integer(),
          recovery_attempts: non_neg_integer(),
          recovery_max_retries: non_neg_integer(),
          recovery_backoff_ms: non_neg_integer(),
          last_health_check: DateTime.t() | nil,
          last_recovery_attempt: DateTime.t() | nil
        }

  # Required callbacks for implementing agents
  @callback handle_message(message(), state()) :: response()

  # Optional callbacks
  @callback handle_handoff(target :: pid(), state()) :: {:ok, state()} | error()
  @callback health_check(state()) :: {:ok, health_status(), state()} | {:error, term()}
  @callback handle_recovery(reason :: term(), state()) :: {:ok, state()} | {:error, term()}

  @optional_callbacks [
    handle_handoff: 2,
    health_check: 1,
    handle_recovery: 2
  ]

  # Configuration constants
  @name_regex ~r/^[a-zA-Z0-9_-]+$/
  @max_name_length 64
  @min_instruction_length 10
  @max_instruction_length 2000

  # Health check defaults
  @default_health_check_interval 30_000
  @default_recovery_max_retries 3
  @default_recovery_backoff_ms 1_000

  defmacro __using__(_opts) do
    regex = Macro.escape(@name_regex)

    quote location: :keep do
      @name_regex unquote(regex)
      @behaviour SwarmEx.Agent

      use GenServer
      require Logger

      alias SwarmEx.{Error, Telemetry, Utils}

      # Default implementations that can be overridden
      @impl true
      @spec init(SwarmEx.Agent.agent_opts()) ::
              {:ok, SwarmEx.Agent.agent_state()} | {:error, term()}
      def init(opts) do
        with :ok <- validate_agent_config(opts) do
          # Initialize health check timer if enabled
          health_check_interval =
            opts[:health_check_interval] || unquote(@default_health_check_interval)

          if health_check_interval > 0 do
            Process.send_after(self(), :health_check, health_check_interval)
          end

          # Build state map with defaults and provided options
          state = %{
            name: opts[:name],
            instruction: opts[:instruction],
            network_id: opts[:network_id],
            network_pid: opts[:network_pid],
            custom_opts: filter_custom_opts(opts),
            started_at: DateTime.utc_now(),
            health_status: :healthy,
            health_check_interval: health_check_interval,
            recovery_attempts: 0,
            recovery_max_retries:
              opts[:recovery_max_retries] || unquote(@default_recovery_max_retries),
            recovery_backoff_ms:
              opts[:recovery_backoff_ms] || unquote(@default_recovery_backoff_ms),
            last_health_check: nil,
            last_recovery_attempt: nil
          }

          {:ok, state}
        else
          {:error, reason} ->
            error = Error.ValidationError.exception(errors: reason)
            Logger.error("Agent initialization failed: #{Exception.message(error)}")
            {:error, error}
        end
      end

      @impl true
      @spec terminate(term(), SwarmEx.Agent.agent_state()) :: :ok
      def terminate(reason, state) do
        # Get network ID for telemetry
        network_id = Map.get(state, :network_id, "default")
        agent_name = Map.get(state, :name, self())

        # Emit telemetry event for agent termination
        :telemetry.execute(
          [:swarm_ex, :agent, :terminate],
          %{timestamp: System.system_time()},
          %{
            network_id: network_id,
            agent: agent_name,
            reason: reason,
            health_status: Map.get(state, :health_status)
          }
        )

        # Log termination for debugging
        Logger.info("Agent #{inspect(agent_name)} terminating with reason: #{inspect(reason)}")

        # Clean up any custom state cleanup defined by the implementing module
        cleanup_result =
          if function_exported?(__MODULE__, :cleanup, 1) do
            try do
              __MODULE__.cleanup(state)
            catch
              kind, error ->
                cleanup_error =
                  Error.AgentError.exception(
                    agent: __MODULE__,
                    reason: {kind, error},
                    message: "Cleanup failed"
                  )

                Logger.error(Exception.message(cleanup_error))
                {:error, cleanup_error}
            end
          else
            :ok
          end

        # Log cleanup result
        case cleanup_result do
          :ok ->
            Logger.debug("Agent cleanup completed successfully")

          {:error, error} ->
            Logger.warning("Agent cleanup completed with error: #{Exception.message(error)}")
        end

        :ok
      end

      @spec handle_handoff(pid(), SwarmEx.Agent.agent_state()) ::
              {:ok, SwarmEx.Agent.agent_state()}
      def handle_handoff(_target, state), do: {:ok, state}

      # Default health check implementation
      @spec health_check(SwarmEx.Agent.agent_state()) ::
              {:ok, SwarmEx.Agent.health_status(), SwarmEx.Agent.agent_state()}
      def health_check(state) do
        {:ok, :healthy, state}
      end

      # Default recovery implementation
      @spec handle_recovery(term(), SwarmEx.Agent.agent_state()) ::
              {:ok, SwarmEx.Agent.agent_state()}
      def handle_recovery(_reason, state) do
        {:ok, state}
      end

      # Allow modules to override these defaults
      defoverridable init: 1,
                     terminate: 2,
                     handle_handoff: 2,
                     health_check: 1,
                     handle_recovery: 2

      @spec start_link(SwarmEx.Agent.agent_opts()) :: GenServer.on_start()
      def start_link(opts) do
        GenServer.start_link(__MODULE__, opts, name: via_tuple(opts[:name]))
      end

      @spec send_message(pid() | atom() | String.t(), term()) ::
              {:ok, term()} | {:error, term()}
      def send_message(agent, message) do
        GenServer.call(via_tuple(agent), {:message, message})
      end

      @spec get_state(pid() | atom() | String.t()) ::
              {:ok, SwarmEx.Agent.agent_state()} | {:error, term()}
      def get_state(agent) do
        GenServer.call(via_tuple(agent), :get_state)
      end

      @spec stop(pid() | atom() | String.t(), term()) :: :ok | {:error, term()}
      def stop(agent, reason \\ :normal) do
        GenServer.stop(via_tuple(agent), reason)
      end

      # GenServer Implementation
      @impl true
      @spec handle_call(term(), GenServer.from(), SwarmEx.Agent.agent_state()) ::
              {:reply, term(), SwarmEx.Agent.agent_state()}
      def handle_call({:message, message}, _from, state) do
        if Map.get(state, :health_status) == :unhealthy do
          error =
            Error.AgentError.exception(
              agent: Map.get(state, :name),
              reason: :unhealthy_agent,
              message: "Agent is in unhealthy state"
            )

          {:reply, {:error, error}, state}
        else
          network_id = Map.get(state, :network_id, "default")

          Telemetry.span_agent_message(self(), :message, network_id, fn ->
            case handle_message(message, state) do
              {:ok, response, new_state} ->
                {:reply, {:ok, response}, new_state}

              {:error, reason} ->
                error =
                  Error.AgentError.exception(
                    agent: Map.get(state, :name),
                    reason: reason,
                    message: "Message handling failed"
                  )

                Logger.error(Exception.message(error))
                attempt_recovery(error, state)
            end
          end)
        end
      end

      @impl true
      def handle_call(:get_state, _from, state) do
        {:reply, {:ok, state}, state}
      end

      @impl true
      @spec handle_info(term(), SwarmEx.Agent.agent_state()) ::
              {:noreply, SwarmEx.Agent.agent_state()}
      def handle_info(:health_check, state) do
        # Schedule next health check
        if Map.get(state, :health_check_interval, 0) > 0 do
          Process.send_after(self(), :health_check, state.health_check_interval)
        end

        # Perform health check
        case health_check(state) do
          {:ok, status, new_state} ->
            # Emit telemetry for health check
            :telemetry.execute(
              [:swarm_ex, :agent, :health_check],
              %{timestamp: System.system_time()},
              %{
                agent: Map.get(state, :name, self()),
                status: status,
                network_id: Map.get(state, :network_id)
              }
            )

            updated_state = %{
              new_state
              | health_status: status,
                last_health_check: DateTime.utc_now()
            }

            # Attempt recovery if health status is degraded or unhealthy
            case status do
              :healthy ->
                {:noreply, updated_state}

              status when status in [:degraded, :unhealthy] ->
                error =
                  Error.AgentError.exception(
                    agent: Map.get(state, :name),
                    reason: {:unhealthy_status, status},
                    message: "Agent health check detected unhealthy status"
                  )

                attempt_recovery(error, updated_state)
            end

          {:error, reason} ->
            error =
              Error.AgentError.exception(
                agent: Map.get(state, :name),
                reason: reason,
                message: "Health check failed"
              )

            Logger.error(Exception.message(error))
            attempt_recovery(error, state)
        end
      end

      @impl true
      def handle_info({:handoff, target}, state) do
        case handle_handoff(target, state) do
          {:ok, new_state} ->
            {:noreply, new_state}

          {:error, reason} ->
            error =
              Error.AgentError.exception(
                agent: Map.get(state, :name),
                reason: reason,
                message: "Handoff failed"
              )

            Logger.error(Exception.message(error))
            {:noreply, state}
        end
      end

      # Recovery handling
      @spec attempt_recovery(Error.AgentError.t(), SwarmEx.Agent.agent_state()) ::
              {:reply, term(), SwarmEx.Agent.agent_state()}
      defp attempt_recovery(error, state) do
        recovery_attempts = Map.get(state, :recovery_attempts, 0)

        recovery_max_retries =
          Map.get(state, :recovery_max_retries, unquote(@default_recovery_max_retries))

        if recovery_attempts >= recovery_max_retries do
          Logger.error("Max recovery attempts reached, agent entering permanent failure state")

          failure_error =
            Error.AgentError.exception(
              agent: Map.get(state, :name),
              reason: :max_recovery_attempts_reached,
              message: "Maximum recovery attempts exceeded"
            )

          {:reply, {:error, failure_error}, %{state | health_status: :unhealthy}}
        else
          # Exponential backoff
          backoff =
            Map.get(state, :recovery_backoff_ms, unquote(@default_recovery_backoff_ms)) *
              :math.pow(2, recovery_attempts)

          Process.sleep(trunc(backoff))

          case handle_recovery(error, state) do
            {:ok, recovered_state} ->
              Logger.info("Agent recovered successfully")

              new_state = %{
                recovered_state
                | recovery_attempts: 0,
                  health_status: :healthy,
                  last_recovery_attempt: DateTime.utc_now()
              }

              {:reply, {:ok, :recovered}, new_state}

            {:error, recovery_error} ->
              recovery_error =
                Error.AgentError.exception(
                  agent: Map.get(state, :name),
                  reason: recovery_error,
                  message: "Recovery attempt failed"
                )

              Logger.warning(Exception.message(recovery_error))

              new_state = %{
                state
                | recovery_attempts: recovery_attempts + 1,
                  health_status: :degraded,
                  last_recovery_attempt: DateTime.utc_now()
              }

              attempt_recovery(recovery_error, new_state)
          end
        end
      end

      # Configuration validation
      @spec validate_agent_config(SwarmEx.Agent.agent_opts()) :: :ok | {:error, term()}
      defp validate_agent_config(opts) do
        with :ok <- validate_name(opts[:name]),
             :ok <- validate_instruction(opts[:instruction]),
             :ok <- validate_network_config(opts),
             :ok <- validate_health_check_config(opts),
             :ok <- validate_custom_opts(opts) do
          :ok
        end
      end

      @spec validate_name(String.t() | nil) :: :ok | {:error, String.t()}
      defp validate_name(nil), do: :ok

      defp validate_name(name) when is_binary(name) do
        cond do
          String.length(name) > unquote(@max_name_length) ->
            {:error,
             "Agent name exceeds maximum length of #{unquote(@max_name_length)} characters"}

          not String.match?(name, @name_regex) ->
            {:error,
             "Agent name contains invalid characters. Use only letters, numbers, underscores, and hyphens"}

          true ->
            :ok
        end
      end

      defp validate_name(_), do: {:error, "Agent name must be a string or nil"}

      @spec validate_instruction(String.t() | nil) :: :ok | {:error, String.t()}
      defp validate_instruction(nil), do: :ok

      defp validate_instruction(instruction) when is_binary(instruction) do
        cond do
          String.length(instruction) < unquote(@min_instruction_length) ->
            {:error,
             "Instruction must be at least #{unquote(@min_instruction_length)} characters"}

          String.length(instruction) > unquote(@max_instruction_length) ->
            {:error,
             "Instruction exceeds maximum length of #{unquote(@max_instruction_length)} characters"}

          true ->
            :ok
        end
      end

      defp validate_instruction(_), do: {:error, "Instruction must be a string or nil"}

      @spec validate_network_config(SwarmEx.Agent.agent_opts()) :: :ok | {:error, String.t()}
      defp validate_network_config(opts) do
        network_id = opts[:network_id]
        network_pid = opts[:network_pid]

        cond do
          is_nil(network_id) and is_nil(network_pid) -> :ok
          is_binary(network_id) and is_pid(network_pid) -> :ok
          is_binary(network_id) -> {:error, "Network PID is required when network_id is provided"}
          is_pid(network_pid) -> {:error, "Network ID is required when network_pid is provided"}
          true -> {:error, "Invalid network configuration"}
        end
      end

      @spec validate_health_check_config(SwarmEx.Agent.agent_opts()) :: :ok | {:error, String.t()}
      defp validate_health_check_config(opts) do
        interval = opts[:health_check_interval] || unquote(@default_health_check_interval)
        max_retries = opts[:recovery_max_retries] || unquote(@default_recovery_max_retries)
        backoff = opts[:recovery_backoff_ms] || unquote(@default_recovery_backoff_ms)

        cond do
          not is_integer(interval) or interval < 0 ->
            {:error, "Health check interval must be a non-negative integer"}

          not is_integer(max_retries) or max_retries < 0 ->
            {:error, "Recovery max retries must be a non-negative integer"}

          not is_integer(backoff) or backoff < 0 ->
            {:error, "Recovery backoff must be a non-negative integer"}

          true ->
            :ok
        end
      end

      @spec validate_custom_opts(SwarmEx.Agent.agent_opts()) :: :ok | {:error, String.t()}
      defp validate_custom_opts(opts) do
        custom_opts = filter_custom_opts(opts)

        if Keyword.keyword?(custom_opts) do
          :ok
        else
          {:error, "Custom options must be a keyword list"}
        end
      end

      @spec filter_custom_opts(SwarmEx.Agent.agent_opts()) :: keyword()
      defp filter_custom_opts(opts) do
        reserved_keys = [
          :name,
          :instruction,
          :network_id,
          :network_pid,
          :health_check_interval,
          :recovery_max_retries,
          :recovery_backoff_ms
        ]

        Keyword.drop(opts, reserved_keys)
      end

      # Private Functions
      @spec via_tuple(String.t() | atom() | pid()) :: {:via, Registry, {atom(), term()}} | pid()
      defp via_tuple(name) when is_binary(name) or is_atom(name) do
        {:via, Registry, {SwarmEx.AgentRegistry, name}}
      end

      defp via_tuple(pid) when is_pid(pid), do: pid
    end
  end

  @doc """
  Validates the agent implementation to ensure all required callbacks are implemented correctly.
  """
  @spec validate_agent(module()) :: :ok | {:error, term()}
  def validate_agent(module) do
    required_callbacks = [{:init, 1}, {:handle_message, 2}]

    missing_callbacks =
      Enum.filter(required_callbacks, fn {fun, arity} ->
        not function_exported?(module, fun, arity)
      end)

    case missing_callbacks do
      [] ->
        :ok

      missing ->
        {:error,
         Error.ValidationError.exception(
           errors:
             "Missing required callbacks: #{inspect(Enum.map(missing, fn {fun, arity} -> "#{fun}/#{arity}" end))}"
         )}
    end
  end

  @doc """
  Creates a new agent process with the given module and options.
  """
  @spec create(module(), keyword()) :: {:ok, pid()} | {:error, term()}
  def create(module, opts \\ []) do
    case validate_agent(module) do
      :ok ->
        name = opts[:name] || Utils.generate_id("agent")
        opts = Keyword.put(opts, :name, name)

        case DynamicSupervisor.start_child(
               SwarmEx.AgentSupervisor,
               {module, Enum.into(opts, %{})}
             ) do
          {:ok, _} = success ->
            success

          {:error, reason} ->
            {:error,
             Error.AgentError.exception(
               agent: module,
               reason: reason,
               message: "Failed to start agent process"
             )}
        end

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Stops an agent process.
  """
  @spec stop(pid() | atom() | binary(), term()) :: :ok | {:error, term()}
  def stop(agent, reason \\ :normal) do
    try do
      GenServer.stop(via_tuple(agent), reason)
    catch
      :exit, {:noproc, _} ->
        {:error,
         Error.AgentError.exception(
           agent: agent,
           reason: :not_found,
           message: "Agent process not found"
         )}
    end
  end

  # Private Functions

  @spec via_tuple(String.t() | atom() | pid()) :: {:via, Registry, {atom(), term()}} | pid()
  defp via_tuple(name) when is_binary(name) or is_atom(name) do
    {:via, Registry, {SwarmEx.AgentRegistry, name}}
  end

  defp via_tuple(pid) when is_pid(pid), do: pid
end
