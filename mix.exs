defmodule SwarmEx.MixProject do
  use Mix.Project

  def project do
    [
      app: :swarm_ex,
      version: "0.1.0",
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "SwarmEx",
      description: "Elixir library for lightweight AI agent orchestration"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {SwarmEx.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jason, "~> 1.4.4"},
      {:telemetry, "~> 1.0"},
      {:uuid, "~> 1.1.8"},
      # For testing
      {:ex_doc, "~> 0.29", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false}
    ]
  end
end
