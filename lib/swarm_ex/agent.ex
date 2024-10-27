defmodule SwarmEx.Agent do
  @moduledoc """
  Defines the behavior for SwarmEx agents and provides the GenServer implementation
  for managing agent processes.

  ## Agent Lifecycle

  Agents go through the following lifecycle stages:
  1. Initialization with `init/1`
  2. Message handling with `handle_message/2`
  3. Tool execution with `handle_tool/2`
  4. Handoffs with `handle_handoff/2`
  5. Termination with `terminate/2`

  ## Example Implementation

    ```

      defmodule MyAgent do
        use SwarmEx.Agent,
          tools: [
            %{
              name: :code_interpreter,
              module: SwarmEx.Tools.CodeInterpreter,
              options: [timeout: 10_000]
            }
          ],
          retry_config: %{
            max_retries: 3,
            base_delay: 100,
            max_delay: 1000
          }

        @impl true
        def init(opts) do
          initial_state = %{
            name: opts[:name],
            context: %{},
            history: []
          }
          {:ok, initial_state}
        end

        @impl true
        def handle_message(message, state) do
          response = process_message(message)
          new_state = update_history(state, message, response)
          {:ok, response, new_state}
        end

        @impl true
        def handle_tool(tool, state) do
          case execute_tool_safely(tool) do
            {:ok, result} ->
              new_state = update_tool_history(state, tool, result)
              {:ok, result, new_state}
            {:error, reason} ->
              {:error, reason}
          end
        end

        @impl true
        def handle_handoff(target_agent, state) do
          # Prepare state for handoff
          handoff_state = prepare_handoff(state)
          {:ok, handoff_state}
        end

        @impl true
        def terminate(reason, state) do
          # Cleanup resources
          cleanup_resources(state)
          :ok
        end
      end

    ```
  """

  alias SwarmEx.{Error, Telemetry}

  @type tool_config :: %{name: atom(), module: module(), options: keyword()}

  @type retry_config :: %{
          max_retries: non_neg_integer(),
          base_delay: non_neg_integer(),
          max_delay: non_neg_integer()
        }

  @type agent_config :: %{
          id: String.t(),
          tools: list(tool_config()),
          retry_config: retry_config(),
          timeout: non_neg_integer()
        }

  @type state :: term()
  @type message :: term()
  @type tool :: term()
  @type error :: {:error, term()}
  @type response :: {:ok, term()} | error()
  @type meta :: %{
          tools: list(tool_config()),
          pending_tools: %{reference() => tool()},
          retry_config: retry_config(),
          correlation_ids: %{reference() => String.t()},
          stats: %{
            message_count: non_neg_integer(),
            tool_executions: non_neg_integer(),
            errors: non_neg_integer()
          }
        }

  @type health_status :: %{
          status: :healthy | :unhealthy,
          stats: map(),
          memory: non_neg_integer(),
          last_message_at: DateTime.t() | nil,
          uptime: non_neg_integer()
        }

  @type validation_error ::
          {:error, :invalid_tools | :invalid_retry_config | :invalid_state, String.t()}

  # Required callbacks
  @callback init(opts :: keyword()) :: {:ok, state()} | error()
  @callback handle_message(message(), state()) :: {:ok, response(), state()} | error()
  @callback handle_handoff(target_agent :: module(), state()) :: {:ok, state()} | error()
  @callback handle_tool(tool(), state()) :: {:ok, response(), state()} | error()
  @callback terminate(reason :: term(), state()) :: term()

  # Default configuration
  @default_retry_config %{
    max_retries: 3,
    base_delay: 100,
    max_delay: 1000
  }

  @default_timeout 5_000

  defmacro __using__(opts) do
    quote location: :keep do
      @behaviour SwarmEx.Agent
      use GenServer
      require Logger

      alias SwarmEx.{Error, Telemetry}

      @tool_config Keyword.get(unquote(opts), :tools, [])
      @retry_config Map.merge(
                      SwarmEx.Agent.get_default_retry_config(),
                      Keyword.get(unquote(opts), :retry_config, %{})
                    )
      @timeout Keyword.get(unquote(opts), :timeout, unquote(@default_timeout))

      @doc """
      Starts a new agent process with the given initialization arguments.
      """
      @spec start_link(keyword()) :: GenServer.on_start()
      def start_link(init_arg) do
        GenServer.start_link(__MODULE__, init_arg)
      end

      @doc """
      Returns the current configuration for this agent.
      """
      @spec get_config() :: SwarmEx.Agent.agent_config()
      def get_config do
        %{
          tools: @tool_config,
          retry_config: @retry_config,
          timeout: @timeout
        }
      end

      @impl true
      def init(init_arg) do
        agent_id = generate_agent_id()
        Logger.metadata(agent_id: agent_id, agent_module: __MODULE__)

        Telemetry.track_operation(
          [:agent, :init],
          fn ->
            with {:ok, config} <- validate_config(get_config()),
                 {:ok, state} <- __MODULE__.init(init_arg),
                 {:ok, validated_state} <- validate_state(state) do
              initial_meta = %{
                tools: @tool_config,
                pending_tools: %{},
                retry_config: @retry_config,
                correlation_ids: %{},
                last_message_at: nil,
                stats: %{
                  message_count: 0,
                  tool_executions: 0,
                  errors: 0
                }
              }

              Logger.info(%{
                event_type: "agent_lifecycle",
                telemetry_event: "agent_started",
                agent_id: agent_id,
                config: %{
                  tools: length(@tool_config),
                  retry_config: @retry_config
                }
              })

              {:ok, {validated_state, initial_meta}}
            else
              {:error, type, reason} ->
                Logger.error(%{
                  event_type: "agent_lifecycle",
                  telemetry_event: "agent_init_failed",
                  agent_id: agent_id,
                  error_type: type,
                  reason: reason
                })

                {:error, reason}
            end
          end,
          %{agent_module: __MODULE__}
        )
      end

      @impl true
      def handle_call({:handle_message, message}, {pid, ref} = from, {state, meta}) do
        correlation_id = generate_correlation_id()
        Logger.metadata(correlation_id: correlation_id)

        new_meta =
          meta
          |> put_in([:correlation_ids, ref], correlation_id)
          |> put_in([:last_message_at], DateTime.utc_now())

        Telemetry.track_operation(
          [:agent, :message],
          fn ->
            case __MODULE__.handle_message(message, state) do
              {:ok, response, new_state} ->
                updated_meta = update_stats(new_meta, :message)
                {:reply, {:ok, response}, {new_state, updated_meta}}

              {:error, reason} = error ->
                Logger.error(%{
                  event_type: "agent_error",
                  telemetry_event: "message_handling_failed",
                  correlation_id: correlation_id,
                  reason: reason,
                  message: inspect(message)
                })

                updated_meta = update_stats(new_meta, :error)
                {:reply, error, {state, updated_meta}}
            end
          end,
          %{
            agent_module: __MODULE__,
            correlation_id: correlation_id,
            message_type: get_message_type(message)
          }
        )
      end

      @impl true
      def handle_call({:handle_tool, tool}, {pid, ref}, {state, meta}) do
        correlation_id = generate_correlation_id()
        Logger.metadata(correlation_id: correlation_id)

        new_meta = put_in(meta.correlation_ids[ref], correlation_id)

        Telemetry.track_operation(
          [:agent, :tool],
          fn ->
            case execute_tool_with_retry(tool, state, meta.retry_config) do
              {:ok, result, new_state} ->
                updated_meta = update_stats(new_meta, :tool)
                {:reply, {:ok, result}, {new_state, updated_meta}}

              {:error, reason} ->
                updated_meta = update_stats(new_meta, :error)

                raise Error.ToolExecutionError,
                  tool: tool,
                  reason: reason,
                  context: %{
                    agent: __MODULE__,
                    correlation_id: correlation_id,
                    retries: meta.retry_config.max_retries
                  }
            end
          end,
          %{
            agent_module: __MODULE__,
            correlation_id: correlation_id,
            tool: tool
          }
        )
      end

      @impl true
      def handle_call(:health_check, _from, {state, meta}) do
        status = generate_health_status(state, meta)
        {:reply, status, {state, meta}}
      end

      @impl true
      def handle_call({:update_context, updates}, _from, {state, meta}) do
        correlation_id = generate_correlation_id()
        Logger.metadata(correlation_id: correlation_id)

        Telemetry.track_operation(
          [:agent, :context],
          fn ->
            new_state = update_in(state.context, &Map.merge(&1, updates))
            {:reply, :ok, {new_state, meta}}
          end,
          %{
            agent_module: __MODULE__,
            correlation_id: correlation_id,
            update_type: :context
          }
        )
      end

      @impl true
      def handle_call(:get_metrics, _from, {state, meta}) do
        metrics = %{
          message_count: meta.stats.message_count,
          tool_executions: meta.stats.tool_executions,
          error_count: meta.stats.errors,
          memory_usage: :erlang.memory(:total),
          process_info: Process.info(self(), [:message_queue_len, :heap_size])
        }

        {:reply, metrics, {state, meta}}
      end

      @impl true
      def handle_call({:handoff, target_agent}, {pid, ref}, {state, meta}) do
        correlation_id = generate_correlation_id()
        Logger.metadata(correlation_id: correlation_id)

        new_meta = put_in(meta.correlation_ids[ref], correlation_id)

        Telemetry.track_operation(
          [:agent, :handoff],
          fn ->
            case __MODULE__.handle_handoff(target_agent, state) do
              {:ok, new_state} ->
                {:reply, :ok, {new_state, new_meta}}

              {:error, reason} ->
                updated_meta = update_stats(new_meta, :error)

                raise Error.HandoffError,
                  source_agent: __MODULE__,
                  target_agent: target_agent,
                  context: %{
                    correlation_id: correlation_id,
                    reason: reason
                  }
            end
          end,
          %{
            agent_module: __MODULE__,
            correlation_id: correlation_id,
            target_agent: target_agent
          }
        )
      end

      @impl true
      def terminate(reason, {state, meta}) do
        Logger.info(%{
          event_type: "agent_lifecycle",
          telemetry_event: "agent_terminating",
          reason: reason,
          stats: meta.stats
        })

        if function_exported?(__MODULE__, :terminate, 2) do
          __MODULE__.terminate(reason, state)
        end
      end

      # Private helpers
      defp execute_tool_with_retry(tool, state, retry_config) do
        try_execute_tool(tool, state, retry_config.max_retries, retry_config)
      end

      defp try_execute_tool(_tool, state, 0, _retry_config) do
        {:error, :max_retries_reached}
      end

      defp try_execute_tool(tool, state, retries, retry_config) do
        case __MODULE__.handle_tool(tool, state) do
          {:ok, _result, _state} = success ->
            success

          {:error, reason} = error ->
            Logger.warning("Tool execution failed",
              tool: tool,
              retries_left: retries,
              error: reason
            )

            case classify_error(reason) do
              :recoverable ->
                delay =
                  calculate_backoff(
                    retry_config.max_retries - retries,
                    retry_config.base_delay,
                    retry_config.max_delay
                  )

                Process.sleep(delay)
                try_execute_tool(tool, state, retries - 1, retry_config)

              :fatal ->
                error
            end
        end
      end

      # Add these helper functions right after try_execute_tool
      defp classify_error(reason) do
        case reason do
          :timeout -> :recoverable
          :rate_limit -> :recoverable
          :network_error -> :recoverable
          _ -> :fatal
        end
      end

      defp calculate_backoff(attempt, base_delay, max_delay) do
        backoff = base_delay * :math.pow(2, attempt)
        min(trunc(backoff), max_delay)
      end

      defp generate_health_status(state, meta) do
        start_time = Process.info(self(), :start_time)
        uptime = System.system_time(:millisecond) - start_time

        %{
          status: determine_health_status(meta),
          stats: meta.stats,
          memory: :erlang.memory(:total),
          last_message_at: Map.get(meta, :last_message_at),
          uptime: uptime
        }
      end

      defp determine_health_status(meta) do
        cond do
          meta.stats.errors > meta.stats.message_count * 0.5 -> :unhealthy
          Process.info(self(), :message_queue_len) > 100 -> :unhealthy
          true -> :healthy
        end
      end

      defp validate_config(config) do
        with :ok <- validate_tools(config.tools),
             :ok <- validate_retry_config(config.retry_config),
             :ok <- validate_timeout(config.timeout),
             # Add this line
             :ok <- validate_custom_rules(config.custom_rules) do
          {:ok, config}
        end
      end

      # Add after the validate_timeout function (around line 435)
      defp validate_custom_rules(nil), do: :ok

      defp validate_custom_rules(rules) when is_map(rules) do
        # Add custom validation logic
        :ok
      end

      defp validate_custom_rules(_),
        do: {:error, :invalid_custom_rules, "Custom rules must be a map"}

      defp validate_tools([]),
        do: {:error, :invalid_tools, "At least one tool must be configured"}

      defp validate_tools(tools) when is_list(tools) do
        tools
        |> Enum.all?(fn tool ->
          is_map(tool) and
            Map.has_key?(tool, :name) and
            Map.has_key?(tool, :module) and
            is_atom(tool.name) and
            is_atom(tool.module)
        end)
        |> case do
          true -> :ok
          false -> {:error, :invalid_tools, "Invalid tool configuration format"}
        end
      end

      defp validate_tools(_), do: {:error, :invalid_tools, "Tools must be a list"}

      defp validate_retry_config(config) do
        with true <- is_map(config),
             true <- is_integer(config.max_retries) and config.max_retries >= 0,
             true <- is_integer(config.base_delay) and config.base_delay > 0,
             true <- is_integer(config.max_delay) and config.max_delay >= config.base_delay do
          :ok
        else
          _ -> {:error, :invalid_retry_config, "Invalid retry configuration"}
        end
      end

      defp validate_timeout(timeout) when is_integer(timeout) and timeout > 0, do: :ok

      defp validate_timeout(_),
        do: {:error, :invalid_timeout, "Timeout must be a positive integer"}

      defp validate_state(state) do
        required_keys = [:id, :context]
        missing_keys = Enum.filter(required_keys, &(!Map.has_key?(state, &1)))

        case missing_keys do
          [] -> {:ok, state}
          keys -> {:error, :invalid_state, "Missing required keys: #{inspect(keys)}"}
        end
      end

      defp get_message_type(message) when is_binary(message), do: :text
      defp get_message_type(%{type: type}), do: type
      defp get_message_type(message) when is_map(message), do: :structured
      defp get_message_type(_), do: :unknown

      defp generate_correlation_id do
        "#{inspect(__MODULE__)}_#{System.unique_integer([:monotonic, :positive])}"
      end

      defp generate_agent_id do
        "agent_#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"
      end

      defp update_stats(meta, :message) do
        put_in(meta.stats.message_count, meta.stats.message_count + 1)
      end

      defp update_stats(meta, :tool) do
        put_in(meta.stats.tool_executions, meta.stats.tool_executions + 1)
      end

      defp update_stats(meta, :error) do
        put_in(meta.stats.errors, meta.stats.errors + 1)
      end

      # Allow overriding of default implementations
      defoverridable init: 1, terminate: 2
    end
  end

  # Module-level public functions
  @doc """
  Checks the health status of the agent.

  Returns a map containing health metrics and status information.
  """
  @spec check_health(pid()) :: health_status()
  def check_health(pid) do
    GenServer.call(pid, :health_check)
  end

  @doc """
  Retrieves current metrics for the agent.

  Returns a map containing various performance and operational metrics.
  """
  @spec get_metrics(pid()) :: map()
  def get_metrics(pid) do
    GenServer.call(pid, :get_metrics)
  end

  @doc """
  Updates the state of the agent with validation.

  Returns `:ok` if successful, or `{:error, reason}` if validation fails.
  """
  @spec update_state(pid(), (state() -> state())) :: :ok | validation_error()
  def update_state(pid, update_fn) do
    GenServer.call(pid, {:update_state, update_fn})
  end

  # Module-level helper functions
  @doc false
  def get_default_retry_config, do: @default_retry_config
end
