defmodule SwarmEx.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # TODO: Add DynamicSupervisor for managing agent processes
      {DynamicSupervisor, strategy: :one_for_one, name: SwarmEx.AgentSupervisor},

      # TODO: Add Registry for tracking agent processes
      {Registry, keys: :unique, name: SwarmEx.AgentRegistry}

      # Other supervision trees will be added here
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: SwarmEx.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
