defmodule SwarmEx.Application do
  @moduledoc """
  The main SwarmEx application supervisor.
  Responsible for starting and supervising core system components.
  """

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Registry for tracking agent processes
      {Registry, keys: :unique, name: SwarmEx.AgentRegistry},

      # DynamicSupervisor for managing agent processes
      {DynamicSupervisor, strategy: :one_for_one, name: SwarmEx.AgentSupervisor}

      # Additional supervisors can be added here
    ]

    # Start telemetry
    SwarmEx.Telemetry.attach()

    # Configure logging
    configure_logging()

    # Start supervisor with restart strategy
    opts = [strategy: :one_for_one, name: SwarmEx.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Optional callback - clean up any resources if the application is stopped
  @impl true
  def stop(_state) do
    :ok
  end

  defp configure_logging do
    # Set log level based on environment
    Application.put_env(:logger, :level, Application.get_env(:swarm_ex, :log_level, :info))

    # Configure log formatting
    Logger.configure(
      truncate: :infinity,
      utc_log: true
    )
  end
end
