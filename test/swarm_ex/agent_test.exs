# File: swarm_ex/test/swarm_ex/agent_test.exs

defmodule SwarmEx.AgentTest do
  use ExUnit.Case, async: true
  doctest SwarmEx.Agent

  defmodule TestAgent do
    @behaviour SwarmEx.Agent

    def init(opts), do: {:ok, opts}

    def handle_message(msg, state) do
      {:ok, "Processed: #{inspect(msg)}", state}
    end

    def handle_handoff(_target, state), do: {:ok, state}

    def handle_tool(_tool, state), do: {:ok, :tool_response, state}
  end

  describe "agent behavior" do
    test "implements required callbacks" do
      assert function_exported?(TestAgent, :init, 1)
      assert function_exported?(TestAgent, :handle_message, 2)
      assert function_exported?(TestAgent, :handle_handoff, 2)
      assert function_exported?(TestAgent, :handle_tool, 2)
    end

    test "initialization" do
      assert {:ok, state} = TestAgent.init(%{test: true})
      assert state.test == true
    end

    test "message handling" do
      assert {:ok, response, _state} = TestAgent.handle_message("test", %{})
      assert response =~ "test"
    end
  end
end
