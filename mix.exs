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
      description: "Elixir library for lightweight AI agent orchestration",
      source_url: "https://github.com/nrrso/swarm_ex",
      homepage_url: "https://github.com/nrrso/swarm_ex",
      package: package(),
      docs: [
        extras: ["README.md"]
      ]
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
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:sobelow, "~> 0.13", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      files: ~w(lib .formatter.exs mix.exs README* LICENSE* CHANGELOG*),
      maintainers: ["Norris Sam Osarenkhoe"],
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/nrrso/swarm_ex"}
      # Other package information...
    ]
  end
end
