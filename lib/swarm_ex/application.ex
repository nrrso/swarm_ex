defmodule SwarmEx.Application do
  @moduledoc """
  The main SwarmEx application supervisor.
  Responsible for starting and supervising core system components.
  """

  use Application
  require Logger

  @type child_spec :: Supervisor.child_spec() | {module(), term()} | module()
  @type start_type :: :normal | {:takeover, node()} | {:failover, node()}

  @impl true
  @spec start(start_type(), term()) :: {:ok, pid()} | {:error, term()}
  def start(_type, _args) do
    children = [
      # Registry for tracking agent processes
      {Registry, keys: :unique, name: SwarmEx.AgentRegistry},

      # Supervisor for agent processes
      {DynamicSupervisor,
       strategy: :one_for_one, name: SwarmEx.AgentSupervisor, max_restarts: 3, max_seconds: 5},

      # Supervisor for client processes
      {SwarmEx.ClientSupervisor, []}

      # Add any additional supervisors here
    ]

    # Start telemetry
    SwarmEx.Telemetry.attach()

    # Configure logging
    configure_logging()

    # Start supervisor with restart strategy
    opts = [strategy: :one_for_one, name: SwarmEx.Supervisor]

    case Supervisor.start_link(children, opts) do
      {:ok, pid} ->
        Logger.info("Started SwarmEx application")
        {:ok, pid}

      {:error, reason} = error ->
        Logger.error("Failed to start SwarmEx application: #{inspect(reason)}")
        error
    end
  end

  @impl true
  @spec stop(term()) :: :ok
  def stop(_state) do
    Logger.info("Stopping SwarmEx application")
    :ok
  end

  @spec configure_logging() :: :ok
  defp configure_logging do
    # Set log level based on environment
    log_level = Application.get_env(:swarm_ex, :log_level, :info)
    Application.put_env(:logger, :level, log_level)

    # Configure log formatting
    Logger.configure(
      truncate: :infinity,
      utc_log: true,
      metadata: [:network_id, :agent_id, :client_id]
    )

    # Add custom formatter if needed
    if formatter = Application.get_env(:swarm_ex, :log_formatter) do
      Logger.configure(formatter: formatter)
    end

    :ok
  end
end
