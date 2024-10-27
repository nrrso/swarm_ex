defmodule SwarmEx.Error do
  @moduledoc """
  Defines custom error types and error handling utilities for SwarmEx.

  This module provides a set of error exceptions specific to different failure modes
  in the SwarmEx system, along with helper functions for error handling and formatting.
  """

  @type error_type :: :agent | :tool | :network | :handoff | :initialization | :unknown
  @type error_severity :: :warning | :error | :critical
  @type error_context :: %{
          timestamp: DateTime.t(),
          network_id: String.t() | nil,
          correlation_id: String.t() | nil,
          metadata: map()
        }

  @doc """
  Creates a standardized error context map.
  """
  @spec create_error_context(keyword()) :: error_context()
  def create_error_context(opts \\ []) do
    %{
      timestamp: DateTime.utc_now(),
      network_id: Keyword.get(opts, :network_id),
      correlation_id: Keyword.get(opts, :correlation_id) || generate_correlation_id(),
      metadata: Keyword.get(opts, :metadata, %{})
    }
  end

  @doc """
  Generates a correlation ID for error tracking.
  """
  @spec generate_correlation_id() :: String.t()
  def generate_correlation_id, do: "err_" <> UUID.uuid4(:hex)

  defmodule HandoffError do
    @moduledoc """
    Raised when an agent handoff operation fails.

    This error indicates a failure in transferring control or state between agents.
    Common causes include:
    - Network connectivity issues
    - State serialization failures
    - Target agent unavailability
    """

    @type t :: %__MODULE__{
            message: String.t(),
            source_agent: atom() | pid(),
            target_agent: atom() | pid(),
            context: SwarmEx.Error.error_context(),
            reason: term()
          }

    defexception [:message, :source_agent, :target_agent, :context, :reason]

    @impl true
    def exception(opts) do
      source_agent = Keyword.fetch!(opts, :source_agent)
      target_agent = Keyword.fetch!(opts, :target_agent)
      reason = Keyword.get(opts, :reason)
      context = Keyword.get(opts, :context, SwarmEx.Error.create_error_context())

      msg =
        case Keyword.get(opts, :message) do
          nil -> "Agent handoff failed from #{inspect(source_agent)} to #{inspect(target_agent)}"
          message -> message
        end

      %__MODULE__{
        message: msg,
        source_agent: source_agent,
        target_agent: target_agent,
        context: context,
        reason: reason
      }
    end

    @impl true
    def message(%{message: message, reason: reason}) when not is_nil(reason) do
      "#{message} (Reason: #{inspect(reason)})"
    end

    def message(%{message: message}), do: message
  end

  defmodule ToolExecutionError do
    @moduledoc """
    Raised when a tool execution fails.

    This error represents failures in tool operations, which may include:
    - Invalid tool parameters
    - Tool timeouts
    - Resource unavailability
    - Internal tool errors
    """

    @type t :: %__MODULE__{
            message: String.t(),
            tool: atom() | {module(), atom()},
            agent: atom() | pid(),
            context: SwarmEx.Error.error_context(),
            reason: term(),
            retryable: boolean()
          }

    defexception [:message, :tool, :agent, :context, :reason, :retryable]

    @impl true
    def exception(opts) do
      tool = Keyword.fetch!(opts, :tool)
      reason = Keyword.fetch!(opts, :reason)
      agent = Keyword.get(opts, :agent)
      context = Keyword.get(opts, :context, SwarmEx.Error.create_error_context())
      retryable = Keyword.get(opts, :retryable, true)

      msg =
        case Keyword.get(opts, :message) do
          nil -> "Tool execution failed for #{inspect(tool)}"
          message -> message
        end

      %__MODULE__{
        message: msg,
        tool: tool,
        agent: agent,
        context: context,
        reason: reason,
        retryable: retryable
      }
    end

    @impl true
    def message(%{message: message, reason: reason, tool: tool}) do
      "#{message} (Tool: #{inspect(tool)}, Reason: #{inspect(reason)})"
    end
  end

  defmodule AgentError do
    @moduledoc """
    Raised when an agent encounters an error during operation.

    This error indicates issues with agent execution, including:
    - Initialization failures
    - Message handling errors
    - State corruption
    - Resource exhaustion
    """

    @type t :: %__MODULE__{
            message: String.t(),
            agent: atom() | pid(),
            context: SwarmEx.Error.error_context(),
            reason: term(),
            severity: SwarmEx.Error.error_severity(),
            type: SwarmEx.Error.error_type()
          }

    defexception [:message, :agent, :context, :reason, :severity, :type]

    @impl true
    def exception(opts) do
      agent = Keyword.fetch!(opts, :agent)
      reason = Keyword.fetch!(opts, :reason)
      context = Keyword.get(opts, :context, SwarmEx.Error.create_error_context())
      severity = Keyword.get(opts, :severity, :error)
      type = Keyword.get(opts, :type, :unknown)

      msg =
        case Keyword.get(opts, :message) do
          nil -> "Agent error occurred in #{inspect(agent)}"
          message -> message
        end

      %__MODULE__{
        message: msg,
        agent: agent,
        context: context,
        reason: reason,
        severity: severity,
        type: type
      }
    end

    @impl true
    def message(%{message: message, reason: reason, severity: severity}) do
      "[#{severity}] #{message} (Reason: #{inspect(reason)})"
    end
  end

  defmodule NetworkError do
    @moduledoc """
    Raised when an error occurs at the network level.

    This error represents system-wide or network-level issues, including:
    - Node communication failures
    - Network partitions
    - Supervisor failures
    - Configuration errors
    """

    @type t :: %__MODULE__{
            message: String.t(),
            network_id: String.t(),
            context: SwarmEx.Error.error_context(),
            reason: term(),
            severity: SwarmEx.Error.error_severity(),
            affected_agents: [atom() | pid()]
          }

    defexception [:message, :network_id, :context, :reason, :severity, :affected_agents]

    @impl true
    def exception(opts) do
      network_id = Keyword.fetch!(opts, :network_id)
      reason = Keyword.fetch!(opts, :reason)

      context =
        Keyword.get(opts, :context, SwarmEx.Error.create_error_context(network_id: network_id))

      severity = Keyword.get(opts, :severity, :error)
      affected_agents = Keyword.get(opts, :affected_agents, [])

      msg =
        case Keyword.get(opts, :message) do
          nil -> "Network error occurred in network #{network_id}"
          message -> message
        end

      %__MODULE__{
        message: msg,
        network_id: network_id,
        context: context,
        reason: reason,
        severity: severity,
        affected_agents: affected_agents
      }
    end

    @impl true
    def message(%{message: message, reason: reason, severity: severity, affected_agents: agents}) do
      agents_str = if length(agents) > 0, do: " (Affected agents: #{inspect(agents)})", else: ""
      "[#{severity}] #{message} (Reason: #{inspect(reason)})#{agents_str}"
    end
  end
end
