defmodule SwarmEx.ClientSupervisor do
  @moduledoc """
  Supervisor for SwarmEx client processes.

  Manages the lifecycle of client processes with proper error handling and restart strategies.
  Each client represents a network of agents and is supervised independently.
  """

  use DynamicSupervisor
  require Logger
  alias SwarmEx.Client

  def start_link(init_arg) do
    DynamicSupervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    DynamicSupervisor.init(
      strategy: :one_for_one,
      max_restarts: 3,
      max_seconds: 5
    )
  end

  @doc """
  Starts a new client process under supervision.
  """
  @spec start_client(keyword()) :: DynamicSupervisor.on_start_child()
  def start_client(opts \\ []) do
    case DynamicSupervisor.start_child(__MODULE__, {Client, opts}) do
      {:ok, pid} = success ->
        Logger.info("Started client process: #{inspect(pid)}")
        success

      {:error, reason} = error ->
        Logger.error("Failed to start client process: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Terminates a client process and all its associated agents.
  """
  @spec terminate_client(pid()) :: :ok | {:error, term()}
  def terminate_client(client_pid) when is_pid(client_pid) do
    case DynamicSupervisor.terminate_child(__MODULE__, client_pid) do
      :ok ->
        Logger.info("Terminated client process: #{inspect(client_pid)}")
        :ok

      {:error, reason} = error ->
        Logger.error(
          "Failed to terminate client process #{inspect(client_pid)}: #{inspect(reason)}"
        )

        error
    end
  end

  @doc """
  Lists all active client processes.
  """
  @spec list_clients() :: [pid()]
  def list_clients do
    DynamicSupervisor.which_children(__MODULE__)
    |> Enum.map(fn {_, pid, _, _} -> pid end)
    |> Enum.filter(&is_pid/1)
  end

  @doc """
  Counts the number of active client processes.
  """
  @spec count_clients() :: non_neg_integer()
  def count_clients do
    DynamicSupervisor.count_children(__MODULE__).active
  end
end
