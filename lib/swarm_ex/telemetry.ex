defmodule SwarmEx.Telemetry do
  @moduledoc """
  Telemetry integration for SwarmEx.
  Provides comprehensive metrics and event tracking for agent activities.

  ## Event Categories

  ### Agent Lifecycle Events
  * `[:swarm_ex, :agent, :init]` - Agent initialization
    * Measurement: `:system_time`
    * Metadata: `:agent_id`, `:network_id`, `:correlation_id`

  * `[:swarm_ex, :agent, :terminate]` - Agent termination
    * Measurement: `:system_time`, `:uptime`
    * Metadata: `:agent_id`, `:network_id`, `:correlation_id`, `:reason`

  ### Message Processing Events
  * `[:swarm_ex, :agent, :message, :start]` - Message processing start
    * Measurement: `:system_time`
    * Metadata: `:agent_id`, `:message_type`, `:network_id`, `:correlation_id`, `:message_size`

  * `[:swarm_ex, :agent, :message, :stop]` - Message processing completion
    * Measurement: `:duration` (microseconds), `:queue_time` (milliseconds)
    * Metadata: `:agent_id`, `:message_type`, `:network_id`, `:correlation_id`, `:result`

  ### Tool Execution Events
  * `[:swarm_ex, :tool, :execute, :start]` - Tool execution start
    * Measurement: `:system_time`
    * Metadata: `:tool_name`, `:agent_id`, `:network_id`, `:correlation_id`, `:args`

  * `[:swarm_ex, :tool, :execute, :stop]` - Tool execution completion
    * Measurement: `:duration` (microseconds)
    * Metadata: `:tool_name`, `:agent_id`, `:network_id`, `:correlation_id`, `:result`

  ### Health and Resource Events
  * `[:swarm_ex, :health, :check]` - Periodic health check
    * Measurement: `:memory` (bytes), `:process_count`, `:message_queue_length`
    * Metadata: `:node`, `:network_id`

  * `[:swarm_ex, :agent, :memory]` - Agent memory usage
    * Measurement: `:memory` (bytes), `:heap_size` (bytes), `:stack_size` (bytes)
    * Metadata: `:agent_id`, `:network_id`
  """

  require Logger

  @typedoc "Correlation ID for request tracing"
  @type correlation_id :: String.t()

  @typedoc "Metadata common to all events"
  @type base_metadata :: %{
          required(:agent_id) => term(),
          required(:network_id) => String.t(),
          required(:correlation_id) => correlation_id(),
          optional(atom()) => term()
        }

  @doc """
  Attaches telemetry event handlers and starts periodic health checks.
  Call this when your application starts.

  ## Options
    * `:health_check_interval` - Interval in milliseconds between health checks. Defaults to 60_000 (1 minute)
  """
  def attach(opts \\ []) do
    health_check_interval = Keyword.get(opts, :health_check_interval, 60_000)

    handlers = [
      {[:swarm_ex, :agent, :init], &handle_agent_lifecycle/4},
      {[:swarm_ex, :agent, :terminate], &handle_agent_lifecycle/4},
      {[:swarm_ex, :agent, :message], &handle_agent_message/4},
      {[:swarm_ex, :tool, :execute], &handle_tool_execution/4},
      {[:swarm_ex, :agent, :handoff], &handle_agent_handoff/4},
      {[:swarm_ex, :health, :check], &handle_health_check/4},
      {[:swarm_ex, :agent, :memory], &handle_agent_memory/4}
    ]

    for {event_name, handler} <- handlers do
      attach_event_handlers(event_name, handler)
    end

    schedule_health_check(health_check_interval)
    :ok
  end

  @doc """
  Generates a new correlation ID for request tracing.
  """
  def generate_correlation_id do
    Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end

  @doc """
  Emits an agent message event with timing and tracing information.
  """
  def span_agent_message(agent_id, message_type, network_id, func) when is_function(func, 0) do
    correlation_id = generate_correlation_id()
    start_time = System.monotonic_time()

    metadata = %{
      agent_id: agent_id,
      message_type: message_type,
      network_id: network_id,
      correlation_id: correlation_id,
      message_size: get_process_message_size()
    }

    :telemetry.execute(
      [:swarm_ex, :agent, :message, :start],
      %{system_time: System.system_time()},
      metadata
    )

    try do
      result = func.()

      :telemetry.execute(
        [:swarm_ex, :agent, :message, :stop],
        %{
          duration: System.monotonic_time() - start_time,
          queue_time: get_queue_time()
        },
        Map.put(metadata, :result, :ok)
      )

      result
    rescue
      error ->
        :telemetry.execute(
          [:swarm_ex, :agent, :message, :exception],
          %{duration: System.monotonic_time() - start_time},
          Map.merge(metadata, %{
            error: error,
            stacktrace: __STACKTRACE__
          })
        )

        reraise error, __STACKTRACE__
    end
  end

  @doc """
  Emits a tool execution event with timing and tracing information.
  """
  def span_tool_execution(tool_name, agent_id, network_id, args, func)
      when is_function(func, 0) do
    correlation_id = generate_correlation_id()
    start_time = System.monotonic_time()

    metadata = %{
      tool_name: tool_name,
      agent_id: agent_id,
      network_id: network_id,
      correlation_id: correlation_id,
      args: args
    }

    :telemetry.execute(
      [:swarm_ex, :tool, :execute, :start],
      %{system_time: System.system_time()},
      metadata
    )

    try do
      result = func.()

      :telemetry.execute(
        [:swarm_ex, :tool, :execute, :stop],
        %{duration: System.monotonic_time() - start_time},
        Map.put(metadata, :result, result)
      )

      result
    rescue
      error ->
        :telemetry.execute(
          [:swarm_ex, :tool, :execute, :exception],
          %{duration: System.monotonic_time() - start_time},
          Map.merge(metadata, %{
            error: error,
            stacktrace: __STACKTRACE__
          })
        )

        reraise error, __STACKTRACE__
    end
  end

  @doc """
  Emits agent memory usage metrics.
  """
  def report_agent_memory(agent_id, network_id) do
    case Process.whereis(agent_id) do
      pid when is_pid(pid) ->
        memory_info = Process.info(pid, [:memory, :heap_size, :stack_size])

        :telemetry.execute(
          [:swarm_ex, :agent, :memory],
          %{
            memory: memory_info[:memory],
            heap_size: memory_info[:heap_size],
            stack_size: memory_info[:stack_size]
          },
          %{agent_id: agent_id, network_id: network_id}
        )

      nil ->
        Logger.warn("Cannot report memory for non-existent agent #{inspect(agent_id)}")
    end
  end

  # Event Handlers
  defp handle_agent_lifecycle(_event_name, measurements, metadata, :init) do
    Logger.info(fn ->
      "Agent #{inspect(metadata.agent_id)} initialized in network #{metadata.network_id} " <>
        "(correlation_id: #{metadata.correlation_id})"
    end)
  end

  defp handle_agent_lifecycle(_event_name, measurements, metadata, :terminate) do
    Logger.info(fn ->
      "Agent #{inspect(metadata.agent_id)} terminated in network #{metadata.network_id} " <>
        "after #{measurements.uptime}ms (correlation_id: #{metadata.correlation_id})"
    end)
  end

  defp handle_agent_message(_event_name, measurements, metadata, :start) do
    Logger.debug(fn ->
      "Agent #{inspect(metadata.agent_id)} started processing #{metadata.message_type} " <>
        "in network #{metadata.network_id} (correlation_id: #{metadata.correlation_id})"
    end)
  end

  defp handle_agent_message(_event_name, measurements, metadata, :stop) do
    Logger.debug(fn ->
      "Agent #{inspect(metadata.agent_id)} completed #{metadata.message_type} " <>
        "in #{measurements.duration}μs (correlation_id: #{metadata.correlation_id})"
    end)
  end

  defp handle_agent_message(_event_name, measurements, metadata, :exception) do
    Logger.error(fn ->
      "Agent #{inspect(metadata.agent_id)} failed processing #{metadata.message_type}: " <>
        "#{Exception.message(metadata.error)} (correlation_id: #{metadata.correlation_id})"
    end)
  end

  defp handle_tool_execution(_event_name, measurements, metadata, :start) do
    Logger.debug(fn ->
      "Tool #{metadata.tool_name} started execution for agent #{inspect(metadata.agent_id)} " <>
        "in network #{metadata.network_id} (correlation_id: #{metadata.correlation_id})"
    end)
  end

  defp handle_tool_execution(_event_name, measurements, metadata, :stop) do
    Logger.debug(fn ->
      "Tool #{metadata.tool_name} completed for agent #{inspect(metadata.agent_id)} " <>
        "in #{measurements.duration}μs (correlation_id: #{metadata.correlation_id})"
    end)
  end

  defp handle_tool_execution(_event_name, measurements, metadata, :exception) do
    Logger.error(fn ->
      "Tool #{metadata.tool_name} failed for agent #{inspect(metadata.agent_id)}: " <>
        "#{Exception.message(metadata.error)} (correlation_id: #{metadata.correlation_id})"
    end)
  end

  defp handle_agent_handoff(_event_name, measurements, metadata, :start) do
    Logger.info(fn ->
      "Starting agent handoff from #{inspect(metadata.source_agent)} to #{inspect(metadata.target_agent)} " <>
        "in network #{metadata.network_id} (correlation_id: #{metadata.correlation_id})"
    end)
  end

  defp handle_agent_handoff(_event_name, measurements, metadata, :stop) do
    Logger.info(fn ->
      "Completed agent handoff in #{measurements.duration}μs (correlation_id: #{metadata.correlation_id})"
    end)
  end

  defp handle_agent_handoff(_event_name, measurements, metadata, :exception) do
    Logger.error(fn ->
      "Failed agent handoff: #{Exception.message(metadata.error)} " <>
        "(correlation_id: #{metadata.correlation_id})"
    end)
  end

  defp handle_health_check(_event_name, measurements, metadata, _) do
    Logger.info(fn ->
      "Health check: #{measurements.process_count} processes, " <>
        "#{measurements.memory} bytes memory usage, " <>
        "#{measurements.message_queue_length} messages queued " <>
        "(network: #{metadata.network_id})"
    end)
  end

  defp handle_agent_memory(_event_name, measurements, metadata, _) do
    Logger.debug(fn ->
      "Agent #{inspect(metadata.agent_id)} memory usage: " <>
        "#{measurements.memory} bytes total, " <>
        "#{measurements.heap_size} bytes heap, " <>
        "#{measurements.stack_size} bytes stack"
    end)
  end

  # Helper Functions

  defp attach_event_handlers(event_name, handler) do
    for suffix <- [:start, :stop, :exception] do
      :telemetry.attach(
        handler_id(event_name ++ [suffix]),
        event_name ++ [suffix],
        handler,
        suffix
      )
    end
  end

  defp handler_id(event_name) do
    {:swarm_ex, event_name}
  end

  defp get_queue_time do
    case Process.info(self(), :message_queue_len) do
      {:message_queue_len, len} -> len
      _ -> 0
    end
  end

  defp get_process_message_size do
    case Process.info(self(), :message_queue_len) do
      {:message_queue_len, len} when len > 0 ->
        Process.info(self(), :messages)
        |> elem(1)
        |> List.first()
        |> :erts_debug.flat_size()

      _ ->
        0
    end
  end

  defp schedule_health_check(interval) do
    Process.send_after(self(), :emit_health_metrics, interval)
  end

  def handle_info(:emit_health_metrics, state) do
    memory = :erlang.memory()
    process_count = :erlang.system_info(:process_count)
    message_queue_length = get_queue_time()

    :telemetry.execute(
      [:swarm_ex, :health, :check],
      %{
        memory: memory[:total],
        process_count: process_count,
        message_queue_length: message_queue_length
      },
      %{
        node: node(),
        network_id: state.network_id
      }
    )

    schedule_health_check(state.health_check_interval)
    {:noreply, state}
  end
end
