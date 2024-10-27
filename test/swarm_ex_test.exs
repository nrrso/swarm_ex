defmodule SwarmExTest do
  use ExUnit.Case
  doctest SwarmEx

  test "greets the world" do
    assert SwarmEx.hello() == :world
  end
end
