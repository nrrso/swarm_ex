defmodule SwarmEx.Telemetry do
  @moduledoc """
  Telemetry integration for SwarmEx.
  Provides metrics and event tracking for agent activities.

  ## Events
  The following events are emitted:

  * `[:swarm_ex, :agent, :message, :start]` - When an agent begins processing a message
    * Measurement: `:system_time`
    * Metadata: `:agent_id`, `:message_type`, `:network_id`

  * `[:swarm_ex, :agent, :message, :stop]` - When an agent completes processing a message
    * Measurement: `:duration`, `:queue_time`
    * Metadata: `:agent_id`, `:message_type`, `:network_id`, `:result`

  * `[:swarm_ex, :tool, :execute, :start]` - When a tool execution begins
    * Measurement: `:system_time`
    * Metadata: `:tool_name`, `:agent_id`, `:args`

  * `[:swarm_ex, :tool, :execute, :stop]` - When a tool execution completes
    * Measurement: `:duration`
    * Metadata: `:tool_name`, `:agent_id`, `:result`
  """

  require Logger

  @doc """
  Attaches telemetry event handlers. Call this when your application starts.
  """
  def attach do
    handlers = [
      {[:swarm_ex, :agent, :message], &handle_agent_message/4},
      {[:swarm_ex, :tool, :execute], &handle_tool_execution/4},
      {[:swarm_ex, :agent, :handoff], &handle_agent_handoff/4}
    ]

    for {event_name, handler} <- handlers do
      :telemetry.attach(
        handler_id(event_name),
        event_name ++ [:start],
        handler,
        :start
      )

      :telemetry.attach(
        handler_id(event_name ++ [:stop]),
        event_name ++ [:stop],
        handler,
        :stop
      )

      :telemetry.attach(
        handler_id(event_name ++ [:exception]),
        event_name ++ [:exception],
        handler,
        :exception
      )
    end

    :ok
  end

  @doc """
  Emits an agent message event with timing information.
  """
  def span_agent_message(agent_id, message_type, func) when is_function(func, 0) do
    start_time = System.monotonic_time()

    :telemetry.execute(
      [:swarm_ex, :agent, :message, :start],
      %{system_time: System.system_time()},
      %{agent_id: agent_id, message_type: message_type}
    )

    try do
      result = func.()

      :telemetry.execute(
        [:swarm_ex, :agent, :message, :stop],
        %{
          duration: System.monotonic_time() - start_time,
          queue_time: get_queue_time()
        },
        %{
          agent_id: agent_id,
          message_type: message_type,
          result: :ok
        }
      )

      result
    rescue
      error ->
        :telemetry.execute(
          [:swarm_ex, :agent, :message, :exception],
          %{duration: System.monotonic_time() - start_time},
          %{
            agent_id: agent_id,
            message_type: message_type,
            error: error,
            stacktrace: __STACKTRACE__
          }
        )

        reraise error, __STACKTRACE__
    end
  end

  @doc """
  Emits a tool execution event with timing information.
  """
  def span_tool_execution(tool_name, agent_id, args, func) when is_function(func, 0) do
    start_time = System.monotonic_time()

    :telemetry.execute(
      [:swarm_ex, :tool, :execute, :start],
      %{system_time: System.system_time()},
      %{tool_name: tool_name, agent_id: agent_id, args: args}
    )

    try do
      result = func.()

      :telemetry.execute(
        [:swarm_ex, :tool, :execute, :stop],
        %{duration: System.monotonic_time() - start_time},
        %{
          tool_name: tool_name,
          agent_id: agent_id,
          result: result
        }
      )

      result
    rescue
      error ->
        :telemetry.execute(
          [:swarm_ex, :tool, :execute, :exception],
          %{duration: System.monotonic_time() - start_time},
          %{
            tool_name: tool_name,
            agent_id: agent_id,
            error: error,
            stacktrace: __STACKTRACE__
          }
        )

        reraise error, __STACKTRACE__
    end
  end

  # Event Handlers
  defp handle_agent_message(_event_name, measurements, metadata, :start) do
    Logger.debug(fn ->
      "Agent #{inspect(metadata.agent_id)} started processing #{metadata.message_type}"
    end)
  end

  defp handle_agent_message(_event_name, measurements, metadata, :stop) do
    Logger.debug(fn ->
      "Agent #{inspect(metadata.agent_id)} completed #{metadata.message_type} in #{measurements.duration}μs"
    end)
  end

  defp handle_agent_message(_event_name, measurements, metadata, :exception) do
    Logger.error(fn ->
      "Agent #{inspect(metadata.agent_id)} failed processing #{metadata.message_type}: #{Exception.message(metadata.error)}"
    end)
  end

  defp handle_tool_execution(_event_name, measurements, metadata, :start) do
    Logger.debug(fn ->
      "Tool #{metadata.tool_name} started execution for agent #{inspect(metadata.agent_id)}"
    end)
  end

  defp handle_tool_execution(_event_name, measurements, metadata, :stop) do
    Logger.debug(fn ->
      "Tool #{metadata.tool_name} completed for agent #{inspect(metadata.agent_id)} in #{measurements.duration}μs"
    end)
  end

  defp handle_tool_execution(_event_name, measurements, metadata, :exception) do
    Logger.error(fn ->
      "Tool #{metadata.tool_name} failed for agent #{inspect(metadata.agent_id)}: #{Exception.message(metadata.error)}"
    end)
  end

  defp handle_agent_handoff(_event_name, measurements, metadata, :start) do
    Logger.info(fn ->
      "Starting agent handoff from #{inspect(metadata.source_agent)} to #{inspect(metadata.target_agent)}"
    end)
  end

  defp handle_agent_handoff(_event_name, measurements, metadata, :stop) do
    Logger.info(fn ->
      "Completed agent handoff from #{inspect(metadata.source_agent)} to #{inspect(metadata.target_agent)} in #{measurements.duration}μs"
    end)
  end

  defp handle_agent_handoff(_event_name, measurements, metadata, :exception) do
    Logger.error(fn ->
      "Failed agent handoff from #{inspect(metadata.source_agent)} to #{inspect(metadata.target_agent)}: #{Exception.message(metadata.error)}"
    end)
  end

  # Helper Functions

  defp handler_id(event_name) do
    {:swarm_ex, event_name}
  end

  defp get_queue_time do
    case Process.info(self(), :message_queue_len) do
      {:message_queue_len, len} -> len
      _ -> 0
    end
  end
end
