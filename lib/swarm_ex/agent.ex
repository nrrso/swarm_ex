defmodule SwarmEx.Agent do
  @moduledoc """
  Defines the behavior and implementation for SwarmEx agents.

  Each agent in the SwarmEx system is a process that can:
  - Process messages from other agents or clients
  - Maintain internal state
  - Participate in agent networks
  - Execute functions from tool modules

  ## Example

      defmodule ClassifyTool do
        def classify(text) do
          # Perform classification
          {:ok, result}
        end
      end

      defmodule MyAgent do
        use SwarmEx.Agent

        def init(opts) do
          # Initialize agent state
          {:ok, opts}
        end

        def handle_message(msg, state) do
          case ClassifyTool.classify(msg) do
            {:ok, result} -> {:ok, result, state}
            error -> error
          end
        end
      end
  """

  require Logger
  alias SwarmEx.{Error, Telemetry, Utils}

  @type state :: term()
  @type message :: term()
  @type error :: {:error, term()}
  @type response :: {:ok, term(), state()} | {:error, term()}

  # Required callbacks for implementing agents
  @callback handle_message(message(), state()) :: response()

  # Optional callbacks
  @callback handle_handoff(target :: pid(), state()) :: {:ok, state()} | error()

  @optional_callbacks [handle_handoff: 2]

  defmacro __using__(opts) do
    quote location: :keep do
      @behaviour SwarmEx.Agent

      use GenServer
      require Logger

      alias SwarmEx.{Error, Telemetry, Utils}

      # Default implementations that can be overridden
      def init(opts), do: {:ok, opts}
      def terminate(_reason, _state), do: :ok
      def handle_handoff(_target, state), do: {:ok, state}

      # Allow modules to override these defaults
      defoverridable init: 1, terminate: 2, handle_handoff: 2

      def start_link(opts) do
        GenServer.start_link(__MODULE__, opts, name: via_tuple(opts[:name]))
      end

      def send_message(agent, message) do
        GenServer.call(via_tuple(agent), {:message, message})
      end

      def get_state(agent) do
        GenServer.call(via_tuple(agent), :get_state)
      end

      def stop(agent, reason \\ :normal) do
        GenServer.stop(via_tuple(agent), reason)
      end

      # GenServer Implementation
      @impl true
      def handle_call({:message, message}, _from, state) do
        network_id = state[:network_id] || "default"

        Telemetry.span_agent_message(self(), :message, network_id, fn ->
          case handle_message(message, state) do
            {:ok, response, new_state} ->
              {:reply, {:ok, response}, new_state}

            {:error, reason} = error ->
              Logger.error("Message handling failed: #{inspect(reason)}")
              {:reply, error, state}
          end
        end)
      end

      @impl true
      def handle_call(:get_state, _from, state) do
        {:reply, {:ok, state}, state}
      end

      @impl true
      def handle_info({:handoff, target}, state) do
        case handle_handoff(target, state) do
          {:ok, new_state} ->
            {:noreply, new_state}

          {:error, reason} ->
            Logger.error("Handoff failed: #{inspect(reason)}")
            {:noreply, state}
        end
      end

      # Private Functions
      defp via_tuple(name) when is_binary(name) or is_atom(name) do
        {:via, Registry, {SwarmEx.AgentRegistry, name}}
      end

      defp via_tuple(pid) when is_pid(pid), do: pid
    end
  end

  @doc """
  Validates the agent implementation to ensure all required callbacks are implemented correctly.
  """
  @spec validate_agent(module()) :: :ok | {:error, term()}
  def validate_agent(module) do
    required_callbacks = [{:init, 1}, {:handle_message, 2}]

    missing_callbacks =
      Enum.filter(required_callbacks, fn {fun, arity} ->
        not function_exported?(module, fun, arity)
      end)

    case missing_callbacks do
      [] ->
        :ok

      missing ->
        {:error,
         "Missing required callbacks: #{inspect(Enum.map(missing, fn {fun, arity} -> "#{fun}/#{arity}" end))}"}
    end
  end

  @doc """
  Creates a new agent process with the given module and options.
  """
  @spec create(module(), keyword()) :: {:ok, pid()} | {:error, term()}
  def create(module, opts \\ []) do
    case validate_agent(module) do
      :ok ->
        name = opts[:name] || Utils.generate_id("agent")
        opts = Keyword.put(opts, :name, name)

        DynamicSupervisor.start_child(
          SwarmEx.AgentSupervisor,
          {module, opts}
        )

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Stops an agent process.
  """
  @spec stop(pid() | atom() | binary(), term()) :: :ok | {:error, term()}
  def stop(agent, reason \\ :normal) do
    try do
      GenServer.stop(via_tuple(agent), reason)
    catch
      :exit, {:noproc, _} -> {:error, :not_found}
    end
  end

  # Private Functions

  defp via_tuple(name) when is_binary(name) or is_atom(name) do
    {:via, Registry, {SwarmEx.AgentRegistry, name}}
  end

  defp via_tuple(pid) when is_pid(pid), do: pid
end
