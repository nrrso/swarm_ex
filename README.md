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
  
  def init(opts), do: {:ok, opts}
  
  def handle_message(msg, state) do
    # Handle the message
    {:ok, response, state}
  end
end

# Add an agent to the network
{:ok, agent_pid} = SwarmEx.create_agent(network, MyAgent)

# Send a message
SwarmEx.send_message(agent_pid, "Hello!")
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