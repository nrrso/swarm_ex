defmodule SwarmEx do
  @moduledoc """
  SwarmEx is an Elixir library for lightweight, controllable, and testable AI agent orchestration.

  It provides a simple API for creating and managing networks of AI agents, with features including:

  - Agent lifecycle management
  - Message routing between agents
  - Tool integration and execution
  - Network state management
  - Error handling and recovery

  ## Example

      # Create a new agent network
      {:ok, network} = SwarmEx.create_network()

      # Define an agent
      defmodule MyAgent do
        use SwarmEx.Agent

        def init(opts), do: {:ok, opts}

        def handle_message(msg, state) do
          {:ok, "Echo: \#{msg}", state}
        end

        def handle_tool(:example, args, state) do
          {:ok, args, state}
        end
      end

      # Add an agent to the network
      {:ok, agent_pid} = SwarmEx.create_agent(network, MyAgent)

      # Send a message to the agent
      {:ok, response} = SwarmEx.send_message(agent_pid, "Hello!")
  """

  alias SwarmEx.{Client, Agent, Tool, Error}

  @type network :: pid()
  @type agent :: pid() | String.t()
  @type message :: term()
  @type response :: {:ok, term()} | {:error, term()}

  @doc """
  Creates a new agent network with the given configuration.

  ## Options

    * `:name` - Optional name for the network
    * `:context` - Initial context map (default: %{})
    * All other options are passed to the underlying Client

  ## Examples

      {:ok, network} = SwarmEx.create_network()
      {:ok, named_network} = SwarmEx.create_network(name: "primary_network")

  """
  @spec create_network(keyword()) :: {:ok, network()} | {:error, term()}
  def create_network(opts \\ []) do
    Client.start_link(opts)
  end

  @doc """
  Creates a new agent in the given network.

  ## Options

    * `:name` - Optional name for the agent
    * `:tools` - List of tools available to the agent
    * `:instruction` - Base instruction/prompt for the agent
    * All other options are passed to the agent's init/1 callback

  ## Examples

      {:ok, agent} = SwarmEx.create_agent(network, MyAgent)
      {:ok, agent} = SwarmEx.create_agent(network, MyAgent, name: "processor")
  """
  @spec create_agent(network(), module(), keyword()) :: {:ok, agent()} | {:error, term()}
  def create_agent(network, agent_module, opts \\ []) do
    Client.create_agent(network, agent_module, opts)
  end

  @doc """
  Sends a message to an agent identified by PID and waits for the response.

  ## Examples

      {:ok, response} = SwarmEx.send_message_to_pid(agent_pid, "Process this")
  """
  @spec send_message_to_pid(pid(), message()) :: response()
  def send_message_to_pid(agent_pid, message) when is_pid(agent_pid) do
    GenServer.call(agent_pid, {:message, message})
  end

  @doc """
  Sends a message to an agent identified by ID within a network and waits for the response.

  ## Examples

      {:ok, response} = SwarmEx.send_message(network, "agent_id", "Process this")
  """
  @spec send_message(network(), String.t(), message()) :: response()
  def send_message(network, agent_id, message) when is_pid(network) and is_binary(agent_id) do
    Client.send_message(network, agent_id, message)
  end

  @doc """
  Lists all active agents in a network.

  ## Examples

      {:ok, agent_ids} = SwarmEx.list_agents(network)
  """
  @spec list_agents(network()) :: {:ok, [String.t()]} | {:error, term()}
  def list_agents(network) do
    Client.list_agents(network)
  end

  @doc """
  Updates the shared context for a network of agents.

  ## Examples

      :ok = SwarmEx.update_context(network, %{key: "value"})
  """
  @spec update_context(network(), map()) :: :ok | {:error, term()}
  def update_context(network, context) when is_map(context) do
    Client.update_context(network, context)
  end

  @doc """
  Registers a new tool that can be used by agents in the network.

  ## Examples

      SwarmEx.register_tool(MyTool, max_retries: 3)
  """
  @spec register_tool(module(), keyword()) :: :ok | {:error, term()}
  def register_tool(tool_module, opts \\ []) do
    Tool.register(tool_module, opts)
  end

  @doc """
  Stops an agent and removes it from its network.

  ## Examples

      :ok = SwarmEx.stop_agent(agent)
      :ok = SwarmEx.stop_agent(agent, :shutdown)
  """
  @spec stop_agent(agent(), term()) :: :ok | {:error, term()}
  def stop_agent(agent, reason \\ :normal) do
    Agent.stop(agent, reason)
  end

  @doc """
  Returns the version of the SwarmEx library.
  """
  @spec version() :: String.t()
  def version, do: "0.1.0"
end
