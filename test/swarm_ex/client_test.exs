# File: swarm_ex/test/swarm_ex/client_test.exs

defmodule SwarmEx.ClientTest do
  use ExUnit.Case, async: true
  doctest SwarmEx.Client

  alias SwarmEx.{Client, Error}

  setup do
    {:ok, client} = Client.start_link()
    %{client: client}
  end

  describe "start_link/1" do
    test "starts client with default options" do
      assert {:ok, pid} = Client.start_link()
      assert is_pid(pid)
    end

    test "starts client with custom options" do
      opts = [context: %{user_id: "123"}]
      assert {:ok, pid} = Client.start_link(opts)

      # TODO: Add assertions for custom options
    end
  end

  describe "send_message/2" do
    test "successfully routes message to agent", %{client: client} do
      # TODO: Implement message routing test
    end

    test "handles invalid message format", %{client: client} do
      # TODO: Implement error handling test
    end
  end

  describe "handoff/3" do
    test "successfully transfers control between agents", %{client: client} do
      # TODO: Implement handoff test
    end

    test "handles handoff errors gracefully", %{client: client} do
      # TODO: Implement error handling test
    end
  end
end
