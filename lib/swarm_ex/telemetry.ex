defmodule SwarmEx.Telemetry do
  @moduledoc """
  Telemetry integration for SwarmEx.
  Provides metrics and event tracking for agent activities.

  ## Event Structure

  All events are prefixed with [:swarm_ex] and follow this pattern:
  - [:swarm_ex, :category, :operation, :status]

  Common measurements:
  - :duration - Time taken in native time units
  - :system_time - System time when the event occurred
  - :memory - Memory usage when relevant

  Common metadata:
  - :network_id - ID of the agent network
  - :agent_id - ID of the agent involved
  - :correlation_id - Request tracking ID
  """

  require Logger

  # Event prefix for all SwarmEx telemetry events
  @prefix [:swarm_ex]

  # Define all possible event combinations
  @events [
    # Network events
    [:network, :create, :start],
    [:network, :create, :stop],
    [:network, :create, :exception],
    [:network, :shutdown, :start],
    [:network, :shutdown, :stop],
    [:network, :shutdown, :exception],

    # Agent lifecycle events
    [:agent, :create, :start],
    [:agent, :create, :stop],
    [:agent, :create, :exception],
    [:agent, :terminate, :start],
    [:agent, :terminate, :stop],
    [:agent, :terminate, :exception],

    # Message events
    [:agent, :message, :start],
    [:agent, :message, :stop],
    [:agent, :message, :exception],

    # Handoff events
    [:agent, :handoff, :start],
    [:agent, :handoff, :stop],
    [:agent, :handoff, :exception],

    # Tool events
    [:tool, :execute, :start],
    [:tool, :execute, :stop],
    [:tool, :execute, :exception],

    # State events
    [:state, :update, :start],
    [:state, :update, :stop],
    [:state, :update, :exception]
  ]

  @doc """
  Attaches telemetry handlers for all SwarmEx events.

  ## Options

    * `:handler_prefix` - Prefix for handler IDs (default: "swarm_ex")
    * `:formatter` - Custom event formatter function
    * `:storage` - Storage backend for metrics (default: ETS)
  """
  @spec attach(keyword()) :: :ok
  def attach(opts \\ []) do
    handler_id = opts[:handler_prefix] || "swarm_ex"
    formatter = opts[:formatter] || (&default_formatter/4)

    for event <- @events do
      :telemetry.attach(
        handler_id <> "." <> Enum.join(event, "."),
        @prefix ++ event,
        &handle_event/4,
        %{formatter: formatter}
      )
    end

    Logger.info(%{
      event_type: "system_status",
      telemetry_event: "handlers_attached",
      handler_prefix: handler_id,
      event_count: length(@events)
    })

    :ok
  end

  @doc """
  Executes a telemetry event with the SwarmEx prefix.

  ## Examples

      execute_event([:agent, :message, :stop], %{duration: 123}, %{agent_id: "agent1"})
  """
  @spec execute_event(list(), map(), map()) :: :ok
  def execute_event(event_name, measurements, metadata \\ %{}) do
    metadata = Map.put(metadata, :timestamp, DateTime.utc_now())
    :telemetry.execute(@prefix ++ event_name, measurements, metadata)
  end

  @doc """
  Tracks the execution time of a function and emits telemetry events.

  ## Examples

      track_operation([:agent, :message], fn ->
        # Operation to measure
        {:ok, result}
      end, %{agent_id: "agent1"})
  """
  @spec track_operation(list(), (-> result), map()) :: result when result: term()
  def track_operation(event_prefix, func, metadata \\ %{}) do
    start_time = System.monotonic_time()
    start_memory = :erlang.memory(:total)

    execute_event(
      event_prefix ++ [:start],
      %{
        system_time: System.system_time(),
        memory: start_memory
      },
      metadata
    )

    try do
      result = func.()
      end_time = System.monotonic_time()
      end_memory = :erlang.memory(:total)

      execute_event(
        event_prefix ++ [:stop],
        %{
          duration: end_time - start_time,
          memory_delta: end_memory - start_memory
        },
        Map.put(metadata, :result, result)
      )

      result
    catch
      kind, reason ->
        execute_event(
          event_prefix ++ [:exception],
          %{
            duration: System.monotonic_time() - start_time
          },
          Map.merge(metadata, %{
            kind: kind,
            reason: reason,
            stacktrace: __STACKTRACE__
          })
        )

        :erlang.raise(kind, reason, __STACKTRACE__)
    end
  end

  # Event emitting helpers

  def emit_agent_message(agent_id, message_type, duration) do
    execute_event([:agent, :message, :stop], %{duration: duration}, %{
      agent_id: agent_id,
      message_type: message_type,
      memory: :erlang.memory(:total)
    })
  end

  def emit_tool_execution(tool_name, duration, result) do
    execute_event([:tool, :execute, :stop], %{duration: duration}, %{
      tool: tool_name,
      result: result,
      memory: :erlang.memory(:total)
    })
  end

  def emit_handoff(from_agent, to_agent, duration, success?) do
    execute_event([:agent, :handoff, :stop], %{duration: duration}, %{
      from_agent: from_agent,
      to_agent: to_agent,
      success: success?,
      memory: :erlang.memory(:total)
    })
  end

  def emit_network_creation(network_id, duration) do
    execute_event([:network, :create, :stop], %{duration: duration}, %{
      network_id: network_id,
      memory: :erlang.memory(:total)
    })
  end

  def emit_agent_creation(agent_id, network_id, duration) do
    execute_event([:agent, :create, :stop], %{duration: duration}, %{
      agent_id: agent_id,
      network_id: network_id,
      memory: :erlang.memory(:total)
    })
  end

  def emit_state_update(agent_id, state_size, duration) do
    execute_event([:state, :update, :stop], %{duration: duration}, %{
      agent_id: agent_id,
      state_size: state_size,
      memory: :erlang.memory(:total)
    })
  end

  # Private Functions

  defp handle_event(event, measurements, metadata, config) do
    formatter = config.formatter
    formatter.(event, measurements, metadata, config)
  rescue
    e ->
      Logger.error(%{
        event_type: "system_error",
        telemetry_event: "handler_error",
        error_details: inspect(e),
        failed_event: event,
        measurements: measurements,
        metadata: metadata
      })
  end

  defp default_formatter(event, measurements, metadata, _config) do
    Logger.debug(%{
      event_type: "telemetry",
      telemetry_event: event,
      measurements: measurements,
      metadata: metadata
    })
  end

  @doc false
  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 500
    }
  end
end
