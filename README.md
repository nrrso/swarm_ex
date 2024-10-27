# SwarmEx

SwarmEx is an Elixir library for lightweight, controllable, and testable AI agent orchestration. It provides primitives for creating and coordinating networks of AI agents, leveraging Elixir's native strengths in concurrency and fault tolerance.

## Installation

The package can be installed by adding `swarm_ex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:swarm_ex, "~> 0.1.0"}
  ]
end
```

## Features

- Lightweight agent orchestration
- Tool integration framework
- Built-in telemetry and observability
- Robust error handling
- Clear developer experience

## Quick Start

```elixir
# Create a new agent network
{:ok, network} = SwarmEx.create_network()

# Define an agent
defmodule MyAgent do
  use SwarmEx.Agent

  opts = [
          id: UUID.uuid4(),
          name: "Agent 47",
          instruction: "You are a helpful agent.",
          tools: %{}
  ]
  
  def init(opts), do: {:ok, opts}
  
  def handle_message(msg, state) do
    # Handle the message
    # call to openai to generate a response and if necessary invoke a tool call
    response = Instructor.chat_completion(
      model: "gpt-3.5-turbo",
      response_model: Triage,
      messages: [
        %{
          role: "user",
          content: msg
        }
      ]
    )
    case response do
      {:ok, reply } -> check_message(reply, state)
      {:error, error } -> SwarmEx.Error.AgentError.exception(
        agent: __MODULE__, reason: error)
    end
  end

  def handle_tool(:translate, msg, state) do
    # call to function, for example text translation via openai 3rds party api
    # or to invoke another agent
    {:ok, response, state}
  end 

  def check_message(%Triage{tool_call: true, tool: :translate, content: msg}, state) do
    handle_tool(:translate, msg, state)
  end
  def check_message(%Triage{tool_call: false, content: msg}, state) do
    {:ok, response, state}
  end 
end

# Add an agent to the network
{:ok, agent_pid} = SwarmEx.create_agent(network, MyAgent)

# Send a message
SwarmEx.send_message(agent_pid, "Hello, how are you!")
```

## Documentation

The docs can be found at [https://hexdocs.pm/swarm_ex](https://hexdocs.pm/swarm_ex).

## Testing

```bash
mix test
```

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b feature/my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature/my-new-feature`)
5. Create new Pull Request

## License

MIT License. See LICENSE for details.