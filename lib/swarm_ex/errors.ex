defmodule SwarmEx.Error do
  @moduledoc """
  Defines custom error types for SwarmEx.

  This module provides a set of structured exceptions for different error scenarios
  that may occur during agent operations. Each error type includes relevant context
  and formatting for better error handling and debugging.

  ## Usage

      raise SwarmEx.Error.HandoffError,
        source_agent: source,
        target_agent: target,
        message: "Custom error message"

      raise SwarmEx.Error.ToolExecutionError,
        tool: tool_name,
        reason: :timeout,
        context: %{attempt: 3}
  """

  defmodule HandoffError do
    @moduledoc """
    Raised when an agent handoff operation fails.

    Contains information about:
    - The source agent attempting the handoff
    - The target agent that was the intended recipient
    - The reason for the failure
    """
    defexception [:message, :source_agent, :target_agent, :context]

    @impl true
    def exception(opts) do
      source_agent = Keyword.fetch!(opts, :source_agent)
      target_agent = Keyword.fetch!(opts, :target_agent)
      context = Keyword.get(opts, :context, %{})
      msg = Keyword.get(opts, :message, "Agent handoff failed")

      %__MODULE__{
        message: msg,
        source_agent: source_agent,
        target_agent: target_agent,
        context: context
      }
    end

    @impl true
    def message(%{message: message} = error) do
      """
      #{message}
      Source Agent: #{inspect(error.source_agent)}
      Target Agent: #{inspect(error.target_agent)}
      #{SwarmEx.Error.format_context(error.context)}
      """
    end
  end

  defmodule ToolExecutionError do
    @moduledoc """
    Raised when a tool execution fails.

    Contains information about:
    - The tool that failed
    - The reason for the failure
    - Additional context about the execution attempt
    """
    defexception [:message, :tool, :reason, :context]

    @impl true
    def exception(opts) do
      tool = Keyword.fetch!(opts, :tool)
      reason = Keyword.fetch!(opts, :reason)
      context = Keyword.get(opts, :context, %{})
      msg = Keyword.get(opts, :message, "Tool execution failed")

      %__MODULE__{
        message: msg,
        tool: tool,
        reason: reason,
        context: context
      }
    end

    @impl true
    def message(%{message: message} = error) do
      """
      #{message}
      Tool: #{inspect(error.tool)}
      Reason: #{inspect(error.reason)}
      #{SwarmEx.Error.format_context(error.context)}
      """
    end
  end

  defmodule AgentError do
    @moduledoc """
    Raised when an agent encounters an operational error.

    Contains information about:
    - The agent that encountered the error
    - The reason for the failure
    - The operation context when the error occurred
    """
    defexception [:message, :agent, :reason, :context]

    @impl true
    def exception(opts) do
      agent = Keyword.fetch!(opts, :agent)
      reason = Keyword.fetch!(opts, :reason)
      context = Keyword.get(opts, :context, %{})
      msg = Keyword.get(opts, :message, "Agent error occurred")

      %__MODULE__{
        message: msg,
        agent: agent,
        reason: reason,
        context: context
      }
    end

    @impl true
    def message(%{message: message} = error) do
      """
      #{message}
      Agent: #{inspect(error.agent)}
      Reason: #{inspect(error.reason)}
      #{SwarmEx.Error.format_context(error.context)}
      """
    end
  end

  defmodule NetworkError do
    @moduledoc """
    Raised when a network-level operation fails.

    Contains information about:
    - The network ID
    - The operation that failed
    - The reason for the failure
    """
    defexception [:message, :network_id, :operation, :reason, :context]

    @impl true
    def exception(opts) do
      network_id = Keyword.fetch!(opts, :network_id)
      operation = Keyword.fetch!(opts, :operation)
      reason = Keyword.fetch!(opts, :reason)
      context = Keyword.get(opts, :context, %{})
      msg = Keyword.get(opts, :message, "Network operation failed")

      %__MODULE__{
        message: msg,
        network_id: network_id,
        operation: operation,
        reason: reason,
        context: context
      }
    end

    @impl true
    def message(%{message: message} = error) do
      """
      #{message}
      Network ID: #{error.network_id}
      Operation: #{inspect(error.operation)}
      Reason: #{inspect(error.reason)}
      #{SwarmEx.Error.format_context(error.context)}
      """
    end
  end

  defmodule ValidationError do
    @moduledoc """
    Raised when configuration or input validation fails.

    Contains information about:
    - The invalid value
    - The expected format/constraints
    - The validation context
    """
    defexception [:message, :value, :constraints, :context]

    @impl true
    def exception(opts) do
      value = Keyword.fetch!(opts, :value)
      constraints = Keyword.fetch!(opts, :constraints)
      context = Keyword.get(opts, :context, %{})
      msg = Keyword.get(opts, :message, "Validation failed")

      %__MODULE__{
        message: msg,
        value: value,
        constraints: constraints,
        context: context
      }
    end

    @impl true
    def message(%{message: message} = error) do
      """
      #{message}
      Invalid Value: #{inspect(error.value)}
      Expected Constraints: #{inspect(error.constraints)}
      #{SwarmEx.Error.format_context(error.context)}
      """
    end
  end

  defmodule TimeoutError do
    @moduledoc """
    Raised when an operation times out.

    Contains information about:
    - The operation that timed out
    - The timeout threshold
    - The execution context
    """
    defexception [:message, :operation, :threshold, :context]

    @impl true
    def exception(opts) do
      operation = Keyword.fetch!(opts, :operation)
      threshold = Keyword.fetch!(opts, :threshold)
      context = Keyword.get(opts, :context, %{})
      msg = Keyword.get(opts, :message, "Operation timed out")

      %__MODULE__{
        message: msg,
        operation: operation,
        threshold: threshold,
        context: context
      }
    end

    @impl true
    def message(%{message: message} = error) do
      """
      #{message}
      Operation: #{inspect(error.operation)}
      Timeout Threshold: #{inspect(error.threshold)}
      #{SwarmEx.Error.format_context(error.context)}
      """
    end
  end

  # Helpers

  def format_context(context) when context == %{}, do: ""

  def format_context(context) do
    context_str =
      context
      |> Enum.map(fn {k, v} -> "#{k}: #{inspect(v)}" end)
      |> Enum.join("\n")

    "Context:\n#{context_str}"
  end
end
