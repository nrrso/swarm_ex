# File: swarm_ex/lib/swarm_ex/tools/tool.ex

defmodule SwarmEx.Tool do
  @moduledoc """
  Defines the behavior for agent tools. Tools provide specific capabilities
  that agents can use to accomplish tasks.
  """

  @type t :: module()
  @type args :: term()
  @type result :: {:ok, term()} | {:error, term()}

  @callback execute(args()) :: result()
  @callback validate(args()) :: :ok | {:error, term()}
  @callback cleanup(args()) :: :ok | {:error, term()}
end
