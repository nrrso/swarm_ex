defmodule SwarmEx do
  @moduledoc """
  SwarmEx is an Elixir library for lightweight, controllable, and testable AI agent orchestration.

  It provides primitives for creating and coordinating networks of AI agents, leveraging Elixir's
  native strengths in concurrency and fault tolerance.

  ## Features

  - Agent lifecycle management
  - Message routing and delivery
  - Tool integration and execution
  - Context variable management
  - Error handling and recovery
  - Telemetry integration
  - Health monitoring

  ## Example

      # Create a new agent network
      {:ok, client} = SwarmEx.create_network(context: %{initial: "state"})

      # Register an agent
      {:ok, agent} = SwarmEx.register_agent(client, MyAgent, id: "agent1")

      # Send a message
      {:ok, response} = SwarmEx.send_message(client, "Hello", to: "agent1")

  """

  alias SwarmEx.{Client, Agent, Error, Telemetry}

  @type client :: GenServer.server()
  @type agent_module :: module()
  @type agent_id :: String.t()
  @type message :: term()
  @type context :: map()
  @type network_opts :: keyword()
  @type agent_opts :: keyword()

  @doc """
  Creates a new agent network with the given options.

  ## Options

    * `:context` - Initial context map
    * `:rate_limit` - Messages per second (optional)
    * `:timeout` - Default operation timeout (optional)
    * `:name` - Name for the network process (optional)

  ## Example

      {:ok, client} = SwarmEx.create_network(
        context: %{workspace: "/tmp"},
        rate_limit: 50
      )
  """
  @spec create_network(network_opts()) :: {:ok, client()} | {:error, term()}
  def create_network(opts \\ []) do
    Telemetry.track_operation(
      [:network, :create],
      fn -> Client.start_link(opts) end,
      %{options: opts}
    )
  end

  @doc """
  Registers a new agent with the network.

  ## Options

    * `:id` - Unique identifier for the agent (required)
    * `:tools` - List of tool configurations (optional)
    * `:retry_config` - Retry configuration for tools (optional)
    * `:timeout` - Operation timeout (optional)

  ## Example

      {:ok, _agent} = SwarmEx.register_agent(client, MyAgent,
        id: "researcher",
        tools: [
          %{name: :search, module: Tools.Search},
          %{name: :write, module: Tools.Writer}
        ]
      )
  """
  @spec register_agent(client(), agent_module(), agent_opts()) ::
          {:ok, pid()} | {:error, term()}
  def register_agent(client, agent_module, opts) do
    agent_id = Keyword.fetch!(opts, :id)

    Telemetry.track_operation(
      [:agent, :register],
      fn ->
        with {:ok, agent_pid} <- GenServer.start_link(agent_module, opts),
             :ok <- Client.register_agent(client, agent_id, agent_pid) do
          {:ok, agent_pid}
        end
      end,
      %{agent_id: agent_id, module: agent_module}
    )
  end

  @doc """
  Sends a message to an agent in the network.

  ## Options

    * `:to` - Target agent ID (required)
    * `:timeout` - Operation timeout (optional)

  ## Example

      {:ok, response} = SwarmEx.send_message(client, "Analyze this text",
        to: "researcher"
      )
  """
  @spec send_message(client(), message(), keyword()) :: {:ok, term()} | {:error, term()}
  def send_message(client, message, opts) do
    target_agent = Keyword.fetch!(opts, :to)
    timeout = Keyword.get(opts, :timeout)

    Client.send_message(client, message, target_agent, timeout: timeout)
  end

  @doc """
  Updates the network context with new values.

  ## Example

      :ok = SwarmEx.update_context(client, %{
        api_key: "new_key",
        workspace: "/new/path"
      })
  """
  @spec update_context(client(), context()) :: :ok | {:error, term()}
  def update_context(client, updates) when is_map(updates) do
    Client.update_context(client, updates)
  end

  @doc """
  Retrieves the current network context or a specific key from it.

  ## Example

      {:ok, context} = SwarmEx.get_context(client)
      {:ok, api_key} = SwarmEx.get_context(client, :api_key)
  """
  @spec get_context(client(), term() | nil) :: {:ok, term()} | {:error, term()}
  def get_context(client, key \\ nil) do
    Client.get_context(client, key)
  end

  @doc """
  Initiates a handoff between two agents.

  ## Example

      :ok = SwarmEx.handoff(client,
        from: "researcher",
        to: "writer"
      )
  """
  @spec handoff(client(), keyword()) :: :ok | {:error, term()}
  def handoff(client, opts) do
    from_agent = Keyword.fetch!(opts, :from)
    to_agent = Keyword.fetch!(opts, :to)

    Client.handoff(client, from_agent, to_agent)
  end

  @doc """
  Returns network health metrics and statistics.

  ## Example

      {:ok, stats} = SwarmEx.get_network_stats(client)
  """
  @spec get_network_stats(client()) :: {:ok, map()} | {:error, term()}
  def get_network_stats(client) do
    Client.get_network_stats(client)
  end

  @doc """
  Retrieves the current state of an agent.

  ## Example

      {:ok, agent_pid} = SwarmEx.get_agent(client, "researcher")
  """
  @spec get_agent(client(), agent_id()) :: {:ok, pid()} | {:error, term()}
  def get_agent(client, agent_id) do
    Client.get_agent(client, agent_id)
  end

  @doc """
  Returns the health status of an agent.

  ## Example

      {:ok, health} = SwarmEx.check_agent_health(client, "researcher")
  """
  @spec check_agent_health(client(), agent_id()) :: {:ok, map()} | {:error, term()}
  def check_agent_health(client, agent_id) do
    with {:ok, agent_pid} <- get_agent(client, agent_id) do
      Agent.check_health(agent_pid)
    end
  end

  @doc """
  Creates a child specification for supervision.

  ## Example

      children = [
        SwarmEx.child_spec(
          context: %{initial: "state"},
          name: MyApp.AgentNetwork
        )
      ]
  """
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts) do
    %{
      id: opts[:name] || __MODULE__,
      start: {__MODULE__, :create_network, [opts]},
      type: :supervisor,
      restart: :permanent,
      shutdown: 5000
    }
  end
end
