defmodule SwarmEx.Message do
  @doc """
  Create a new chat message.
  """

  @typedoc "ChatMessage structure"
  @type t :: %__MODULE__{
          role: role(),
          content: content(),
          agent: agent()
        }

  @typedoc "role"
  @type role :: :user | :assistant | :system

  @typedoc "content"
  @type content :: String.t()

  @typedoc "agent"
  @type agent :: String.t() | nil

  defstruct role: :user,
            content: %{},
            agent: nil
end
