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
  alias SwarmEx.{Agent, Message, Utils, Error}

  @typedoc "Client state structure"
  @type t :: %__MODULE__{
          context: context(),
          active_agents: agents_map(),
          network_id: network_id(),
          options: keyword()
        }

  @typedoc "Network context map containing shared state"
  @type context :: %{
          optional(atom() | String.t()) => term(),
          messages: [Message.t()]
        }

  @typedoc "Map of agent IDs to their process IDs"
  @type agents_map :: %{optional(agent_id()) => pid()}

  @typedoc "Network identifier"
  @type network_id :: String.t()

  @typedoc "Agent identifier"
  @type agent_id :: String.t()

  @typedoc "Client options for initialization"
  @type client_opts :: [
          name: atom() | String.t(),
          network_id: network_id(),
          context: context(),
          registry: atom()
        ]

  defstruct context: %{messages: []},
            active_agents: %{},
            network_id: nil,
            options: []

  # Client API

  @doc """
  Starts a new agent network with the given options.

  ## Options
    * `:network_id` - Custom identifier for the network (optional)
    * `:context` - Initial context map (default: %{messages: []})
    * `:registry` - Custom registry for agent processes (optional)
  """
  @spec start_link(client_opts()) :: GenServer.on_start()
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
  Expects a Message struct and returns a Message struct response.
  """
  @spec send_message(GenServer.server(), agent_id(), Message.t()) ::
          {:ok, Message.t()} | {:error, term()}
  def send_message(client, agent_id, %Message{} = message) do
    GenServer.call(client, {:send_message, agent_id, message})
  end

  @doc """
  Updates the network context with new values.
  """
  @spec update_context(GenServer.server(), context()) :: {:ok, context()} | {:error, term()}
  def update_context(client, context) when is_map(context) do
    GenServer.call(client, {:update_context, context})
  end

  @doc """
  Gets the current network context.
  """
  @spec get_context(GenServer.server()) :: {:ok, context()} | {:error, term()}
  def get_context(client) do
    GenServer.call(client, :get_context)
  end

  @doc """
  Lists all active agents in the network.
  """
  @spec list_agents(GenServer.server()) :: {:ok, [agent_id()]} | {:error, term()}
  def list_agents(client) do
    GenServer.call(client, :list_agents)
  end

  @doc """
  Syncs the current context with a specific agent.
  """
  @spec sync_context(GenServer.server(), agent_id()) :: {:ok, context()} | {:error, term()}
  def sync_context(client, agent_id) do
    GenServer.call(client, {:sync_agent_context, agent_id})
  end

  # Server Callbacks

  @impl true
  @spec init(client_opts()) :: {:ok, t()}
  def init(opts) do
    network_id = opts[:network_id] || Utils.generate_id("network")
    context = opts[:context] || %{}
    # Ensure messages list exists in context
    context = Map.put_new(context, :messages, [])

    state = %__MODULE__{
      network_id: network_id,
      context: context,
      options: opts
    }

    {:ok, state}
  end

  @impl true
  @spec handle_call(term(), GenServer.from(), t()) ::
          {:reply, term(), t()}
  def handle_call({:create_agent, agent_module, opts}, _from, state) do
    opts =
      Keyword.merge(opts,
        network_id: state.network_id,
        network_pid: self(),
        context: state.context
      )

    case Agent.create(agent_module, opts) do
      {:ok, pid} ->
        agent_id = opts[:name] || Utils.generate_id("agent")
        new_agents = Map.put(state.active_agents, agent_id, pid)

        Process.monitor(pid)

        # Sync context after creation
        case sync_agent_context(pid, state.context) do
          :ok ->
            {:reply, {:ok, pid}, %{state | active_agents: new_agents}}

          {:error, _} = error ->
            {:reply, error, state}
        end

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  def handle_call({:send_message, agent_id, %Message{} = message}, _from, state) do
    case Map.fetch(state.active_agents, agent_id) do
      {:ok, pid} ->
        # Sync context before sending message
        case sync_agent_context(pid, state.context) do
          :ok ->
            # Update message with agent ID if not set
            message = %{message | agent: agent_id}

            # Update context with user message
            state = update_messages(state, message)

            # Send to agent and expect Message struct response
            case GenServer.call(pid, {:message, message}) do
              {:ok, %Message{} = reply} ->
                # Update context with agent's reply
                state = update_messages(state, reply)
                {:reply, {:ok, reply}, state}

              {:error, _} = error ->
                {:reply, error, state}
            end

          {:error, _} = error ->
            {:reply, error, state}
        end

      :error ->
        {:reply, {:error, :agent_not_found}, state}
    end
  end

  def handle_call({:sync_agent_context, agent_id}, _from, state) do
    case Map.fetch(state.active_agents, agent_id) do
      {:ok, pid} ->
        case sync_agent_context(pid, state.context) do
          :ok -> {:reply, {:ok, state.context}, state}
          error -> {:reply, error, state}
        end

      :error ->
        {:reply, {:error, :agent_not_found}, state}
    end
  end

  def handle_call({:update_context, new_context}, _from, state) do
    # Ensure we don't lose the messages list when updating context
    messages = state.context.messages
    updated_context = new_context |> Map.merge(state.context) |> Map.put(:messages, messages)

    # Sync new context with all agents
    results =
      Enum.map(state.active_agents, fn {_id, pid} ->
        sync_agent_context(pid, updated_context)
      end)

    case Enum.find(results, &match?({:error, _}, &1)) do
      nil ->
        {:reply, {:ok, updated_context}, %{state | context: updated_context}}

      error ->
        {:reply, error, state}
    end
  end

  def handle_call(:get_context, _from, state) do
    {:reply, {:ok, state.context}, state}
  end

  def handle_call(:list_agents, _from, state) do
    agents = Map.keys(state.active_agents)
    {:reply, {:ok, agents}, state}
  end

  @impl true
  @spec handle_info(term(), t()) :: {:noreply, t()}
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

  @spec via_tuple(atom() | String.t()) :: {:via, Registry, {atom(), term()}}
  defp via_tuple(name) when is_binary(name) or is_atom(name) do
    {:via, Registry, {SwarmEx.AgentRegistry, {:client, name}}}
  end

  @spec find_agent_id(agents_map(), pid()) :: {:ok, agent_id()} | :error
  defp find_agent_id(agents, target_pid) do
    case Enum.find(agents, fn {_id, pid} -> pid == target_pid end) do
      {id, _pid} -> {:ok, id}
      nil -> :error
    end
  end

  @spec update_messages(t(), Message.t()) :: t()
  defp update_messages(state, message) do
    messages = [message | state.context.messages]
    context = Map.put(state.context, :messages, messages)
    %{state | context: context}
  end

  @spec sync_agent_context(pid(), context()) :: :ok | {:error, term()}
  defp sync_agent_context(pid, context) do
    try do
      GenServer.call(pid, {:sync_context, context})
    catch
      :exit, reason ->
        {:error,
         Error.AgentError.exception(
           agent: pid,
           reason: reason,
           message: "Failed to sync context with agent"
         )}
    end
  end
end
