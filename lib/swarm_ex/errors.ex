defmodule SwarmEx.Error do
  @moduledoc """
  Defines error types for the SwarmEx library.
  """

  defmodule AgentError do
    @moduledoc "Raised when an agent encounters an error"

    @type t :: %__MODULE__{
            message: String.t(),
            agent: term(),
            reason: term()
          }

    defexception [:message, :agent, :reason]

    @impl true
    @spec exception(keyword()) :: t()
    def exception(opts) do
      agent = opts[:agent]
      reason = opts[:reason]
      msg = opts[:message] || "Agent error occurred in #{inspect(agent)}: #{inspect(reason)}"
      %__MODULE__{message: msg, agent: agent, reason: reason}
    end
  end

  defmodule NetworkError do
    @moduledoc "Raised when a network operation fails"

    @type t :: %__MODULE__{
            message: String.t(),
            network_id: String.t() | nil,
            reason: term()
          }

    defexception [:message, :network_id, :reason]

    @impl true
    @spec exception(keyword()) :: t()
    def exception(opts) do
      network_id = opts[:network_id]
      reason = opts[:reason]

      msg =
        opts[:message] || "Network error occurred in #{inspect(network_id)}: #{inspect(reason)}"

      %__MODULE__{message: msg, network_id: network_id, reason: reason}
    end
  end

  defmodule ClientError do
    @moduledoc "Raised when a client operation fails"

    @type t :: %__MODULE__{
            message: String.t(),
            client: term(),
            reason: term()
          }

    defexception [:message, :client, :reason]

    @impl true
    @spec exception(keyword()) :: t()
    def exception(opts) do
      client = opts[:client]
      reason = opts[:reason]
      msg = opts[:message] || "Client error occurred in #{inspect(client)}: #{inspect(reason)}"
      %__MODULE__{message: msg, client: client, reason: reason}
    end
  end

  defmodule ValidationError do
    @moduledoc "Raised when validation fails"

    @type t :: %__MODULE__{
            message: String.t(),
            errors: term()
          }

    defexception [:message, :errors]

    @impl true
    @spec exception(keyword()) :: t()
    def exception(opts) do
      errors = opts[:errors]
      msg = opts[:message] || "Validation failed: #{inspect(errors)}"
      %__MODULE__{message: msg, errors: errors}
    end
  end

  defmodule ToolError do
    @moduledoc "Raised when a tool operation fails"

    @type t :: %__MODULE__{
            message: String.t(),
            tool: atom() | String.t(),
            reason: term()
          }

    defexception [:message, :tool, :reason]

    @impl true
    @spec exception(keyword()) :: t()
    def exception(opts) do
      tool = opts[:tool]
      reason = opts[:reason]
      msg = opts[:message] || "Tool error occurred in #{inspect(tool)}: #{inspect(reason)}"
      %__MODULE__{message: msg, tool: tool, reason: reason}
    end
  end
end
