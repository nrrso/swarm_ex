# File: swarm_ex/lib/swarm_ex/utils.ex

defmodule SwarmEx.Utils do
  @moduledoc """
  Utility functions for SwarmEx operations.
  Provides helper functions for common operations across the library.
  """

  require Logger
  alias SwarmEx.{Error, Telemetry}

  @default_timeout 5_000
  @sensitive_keys [:password, :token, :secret, :api_key]

  @doc """
  Safely executes a function with timeout and retry logic.
  """
  @spec safely_execute(function(), keyword()) ::
          {:ok, term()} | {:error, term()}
  def safely_execute(fun, opts \\ []) do
    timeout = opts[:timeout] || 5_000
    retries = opts[:retries] || 3

    # TODO: Implement retry logic with exponential backoff
    {:error, :not_implemented}
  end

  @doc """
  Validates a map against a schema of required and optional keys.
  """
  @spec validate_schema(map(), keyword()) :: :ok | {:error, term()}
  def validate_schema(map, schema) do
    # TODO: Implement schema validation
    {:error, :not_implemented}
  end

  @doc """
  Formats an error tuple into a standardized error structure.
  """
  @spec format_error(term()) :: Error.t()
  def format_error(error) do
    # TODO: Implement error formatting
    {:error, :not_implemented}
  end

  @doc """
  Generates a unique identifier with an optional prefix.
  """
  @spec generate_id(String.t() | nil) :: String.t()
  def generate_id(prefix \\ nil) do
    uuid = UUID.uuid4()
    if prefix, do: "#{prefix}_#{uuid}", else: uuid
  end

  @doc """
  Serializes a term into a string representation.
  """
  @spec serialize(term()) :: {:ok, String.t()} | {:error, term()}
  def serialize(term) do
    # TODO: Implement serialization
    {:error, :not_implemented}
  end

  @doc """
  Deserializes a string back into a term.
  """
  @spec deserialize(String.t()) :: {:ok, term()} | {:error, term()}
  def deserialize(string) do
    # TODO: Implement deserialization
    {:error, :not_implemented}
  end

  @doc """
  Logs a message with additional context and metadata.
  """
  @spec log(atom(), String.t(), keyword()) :: :ok
  def log(level, message, metadata \\ []) do
    # TODO: Implement structured logging
    Logger.log(level, message, metadata)
  end

  @doc """
  Deep merges two maps recursively.
  """
  @spec deep_merge(map(), map()) :: map()
  def deep_merge(left, right) do
    # TODO: Implement deep merge
    Map.merge(left, right)
  end

  # """
  # Helper functions and utilities for agent implementations.
  # These functions are meant to be used by agent implementations to handle common tasks.
  # """

  @doc """
  Validates a tool configuration map.

  ## Example

      iex> SwarmEx.Agent.validate_tool_config(%{name: :retriever, module: DataRetriever})
      :ok
      iex> SwarmEx.Agent.validate_tool_config(%{name: :invalid})
      {:error, :missing_module}
  """
  @spec validate_tool_config(SwarmEx.Agent.tool_config()) :: :ok | {:error, term()}
  def validate_tool_config(config) do
    with :ok <- validate_required_keys(config, [:name, :module]),
         :ok <- validate_tool_module(config.module) do
      :ok
    end
  end

  @doc """
  Creates a new correlation context for tracking operations.

  ## Example

      iex> context = SwarmEx.Agent.create_correlation_context("agent_123")
      iex> context.correlation_id
      "agent_123_1234567"
  """
  @spec create_correlation_context(String.t()) :: map()
  def create_correlation_context(prefix) do
    %{
      correlation_id: "#{prefix}_#{System.unique_integer([:monotonic, :positive])}",
      started_at: System.system_time(),
      context: %{}
    }
  end

  @doc """
  Generates metrics for the agent's current state.

  ## Example

      iex> metrics = SwarmEx.Agent.generate_metrics(state, meta)
      iex> metrics.message_count
      42
  """
  @spec generate_metrics(term(), SwarmEx.Agent.meta()) :: map()
  def generate_metrics(state, meta) do
    %{
      message_count: meta.stats.message_count,
      tool_executions: meta.stats.tool_executions,
      error_rate: calculate_error_rate(meta.stats),
      memory_usage: :erlang.memory(:total),
      state_size: :erts_debug.flat_size(state)
    }
  end

  @doc """
  Sanitizes sensitive information from the agent state.

  ## Example

      iex> sanitized = SwarmEx.Agent.sanitize_state(%{password: "secret", data: "public"})
      iex> sanitized.password
      "[REDACTED]"
  """
  @spec sanitize_state(term()) :: term()
  def sanitize_state(state) when is_map(state) do
    state
    |> Map.drop(@sensitive_keys)
    |> Map.new(fn
      {k, v} when is_map(v) -> {k, sanitize_state(v)}
      {k, v} when is_list(v) -> {k, Enum.map(v, &sanitize_state/1)}
      kv -> kv
    end)
  end

  def sanitize_state(state) when is_list(state) do
    Enum.map(state, &sanitize_state/1)
  end

  def sanitize_state(state), do: state

  @doc """
  Creates a safe execution environment for tool operations.

  ## Example

      iex> SwarmEx.Agent.create_tool_context(tool_config)
      %{sandbox: pid, timeout: 5000}
  """
  @spec create_tool_context(SwarmEx.Agent.tool_config()) :: map()
  def create_tool_context(tool_config) do
    %{
      sandbox: setup_tool_sandbox(),
      timeout: tool_config[:timeout] || @default_timeout,
      retries_remaining: tool_config[:max_retries] || 3,
      context: %{}
    }
  end

  # Private Utilities

  defp validate_required_keys(config, keys) do
    missing = Enum.filter(keys, &(not Map.has_key?(config, &1)))
    if Enum.empty?(missing), do: :ok, else: {:error, {:missing_keys, missing}}
  end

  defp validate_tool_module(module) when is_atom(module) do
    if Code.ensure_loaded?(module) and function_exported?(module, :execute, 2) do
      :ok
    else
      {:error, :invalid_tool_module}
    end
  end

  defp validate_tool_module(_), do: {:error, :invalid_tool_module}

  defp calculate_error_rate(%{message_count: 0}), do: 0.0

  defp calculate_error_rate(%{message_count: total, errors: errors}) do
    errors / total * 100
  end

  defp setup_tool_sandbox do
    # Implementation would vary based on security requirements
    # This is a placeholder for the actual sandbox implementation
    {:ok, pid} = Task.Supervisor.start_link()
    pid
  end

  # Runtime Configuration Management

  @doc false
  def merge_configs(default_config, user_config) do
    DeepMerge.deep_merge(default_config, user_config)
  end

  @doc false
  def validate_retry_config(%{max_retries: max} = config) when max >= 0 do
    with true <- is_integer(config.base_delay),
         true <- is_integer(config.max_delay),
         true <- config.base_delay > 0,
         true <- config.max_delay >= config.base_delay do
      {:ok, config}
    else
      _ -> {:error, :invalid_retry_config}
    end
  end

  def validate_retry_config(_), do: {:error, :invalid_retry_config}

  # Telemetry Integration Helpers

  @doc false
  def emit_tool_metric(tool_name, duration, result, meta) do
    Telemetry.execute_event(
      [:agent, :tool, :execution],
      %{duration: duration},
      Map.merge(meta, %{
        tool: tool_name,
        result: result,
        memory: :erlang.memory(:total)
      })
    )
  end

  @doc false
  def emit_agent_metric(event_type, measurements, meta) do
    Telemetry.execute_event(
      [:agent, event_type],
      measurements,
      Map.merge(meta, %{
        memory: :erlang.memory(:total),
        timestamp: DateTime.utc_now()
      })
    )
  end
end
