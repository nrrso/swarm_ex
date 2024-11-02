defmodule SwarmEx.Client do
  @moduledoc """
  Main supervisor for agent networks. Manages agent lifecycles,
  message passing, error recovery and context variables.

  The Client acts as a coordinator for a network of AI agents, handling:
  - Agent lifecycle management (creation, termination)
  - Message routing between agents
  - Network state and context maintenance
  - Error handling and recovery
  """

  use GenServer
  require Logger
  alias SwarmEx.{Agent, Utils}

  @type t :: %__MODULE__{
          context: map(),
          active_agents: %{optional(String.t()) => pid()},
          network_id: String.t(),
          options: keyword()
        }

  defstruct context: %{},
            active_agents: %{},
            network_id: nil,
            options: []

  # Client API

  @doc """
  Starts a new agent network with the given options.

  ## Options
    * `:network_id` - Custom identifier for the network (optional)
    * `:context` - Initial context map (default: %{})
    * `:registry` - Custom registry for agent processes (optional)
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name)

    case name do
      nil -> GenServer.start_link(__MODULE__, opts)
      name -> GenServer.start_link(__MODULE__, opts, name: via_tuple(name))
    end
  end

  @doc """
  Creates a new agent in the network.

  ## Options
  All options are passed to the agent's init function.
  """
  @spec create_agent(GenServer.server(), module(), keyword()) ::
          {:ok, pid()} | {:error, term()}
  def create_agent(client, agent_module, opts \\ []) do
    GenServer.call(client, {:create_agent, agent_module, opts})
  end

  @doc """
  Sends a message to a specific agent in the network.
  """
  @spec send_message(GenServer.server(), String.t(), term()) ::
          {:ok, term()} | {:error, term()}
  def send_message(client, agent_id, message) do
    GenServer.call(client, {:send_message, agent_id, message})
  end

  @doc """
  Updates the network context with new values.
  """
  @spec update_context(GenServer.server(), map()) :: {:ok, map()} | {:error, term()}
  def update_context(client, context) when is_map(context) do
    GenServer.call(client, {:update_context, context})
  end

  @doc """
  Gets the current network context.
  """
  @spec get_context(GenServer.server()) :: {:ok, map()} | {:error, term()}
  def get_context(client) do
    GenServer.call(client, :get_context)
  end

  @doc """
  Lists all active agents in the network.
  """
  @spec list_agents(GenServer.server()) :: {:ok, [String.t()]} | {:error, term()}
  def list_agents(client) do
    GenServer.call(client, :list_agents)
  end

  # Server Callbacks

  @impl true
  def init(opts) do
    network_id = opts[:network_id] || Utils.generate_id("network")

    state = %__MODULE__{
      network_id: network_id,
      context: opts[:context] || %{},
      options: opts
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:create_agent, agent_module, opts}, _from, state) do
    opts = Keyword.merge(opts, network_id: state.network_id, context: state.context)

    case Agent.create(agent_module, opts) do
      {:ok, pid} ->
        agent_id = opts[:name] || Utils.generate_id("agent")
        new_agents = Map.put(state.active_agents, agent_id, pid)

        Process.monitor(pid)

        {:reply, {:ok, pid}, %{state | active_agents: new_agents}}

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:send_message, agent_id, message}, _from, state) do
    case Map.fetch(state.active_agents, agent_id) do
      {:ok, pid} ->
        result = GenServer.call(pid, {:message, message})
        {:reply, result, state}

      :error ->
        {:reply, {:error, :agent_not_found}, state}
    end
  end

  @impl true
  def handle_call({:update_context, new_context}, _from, state) do
    updated_context = Map.merge(state.context, new_context)
    {:reply, {:ok, updated_context}, %{state | context: updated_context}}
  end

  @impl true
  def handle_call(:get_context, _from, state) do
    {:reply, {:ok, state.context}, state}
  end

  @impl true
  def handle_call(:list_agents, _from, state) do
    agents = Map.keys(state.active_agents)
    {:reply, {:ok, agents}, state}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, reason}, state) do
    # Handle agent process termination
    case find_agent_id(state.active_agents, pid) do
      {:ok, agent_id} ->
        new_agents = Map.delete(state.active_agents, agent_id)

        Logger.info("Agent #{agent_id} terminated: #{inspect(reason)}")

        {:noreply, %{state | active_agents: new_agents}}

      :error ->
        {:noreply, state}
    end
  end

  # Private Functions

  defp via_tuple(name) when is_binary(name) or is_atom(name) do
    {:via, Registry, {SwarmEx.AgentRegistry, {:client, name}}}
  end

  defp find_agent_id(agents, target_pid) do
    case Enum.find(agents, fn {_id, pid} -> pid == target_pid end) do
      {id, _pid} -> {:ok, id}
      nil -> :error
    end
  end
end
