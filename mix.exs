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
      extra_applications: [:logger, :httpoison],
      mod: {SwarmEx.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:httpoison, "~> 2.2.1"},
      {:jason, "~> 1.4.4"},
      {:openai_ex, "~> 0.8.4"},
      {:ecto, "~> 3.12.4"},
      {:telemetry, "~> 1.0"},
      {:uuid, "~> 1.1.8"},
      {:deep_merge, "~> 1.0"},
      # Add instructor_ex
      {:instructor, "~> 0.0.5"},
      # For testing
      {:ex_doc, "~> 0.29", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false}
    ]
  end
end
