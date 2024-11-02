defmodule SwarmEx.Utils do
  @moduledoc """
  Utility functions for SwarmEx operations.
  Provides helper functions for common operations across the library.
  """

  require Logger
  alias SwarmEx.Error

  @typedoc "Options for retry operations"
  @type retry_opts :: [
          timeout: non_neg_integer(),
          retries: non_neg_integer(),
          backoff_base: non_neg_integer(),
          backoff_type: :exponential | :linear
        ]

  @typedoc "Schema validation options"
  @type schema_opts :: [
          required: [atom()],
          optional: [atom()]
        ]

  @typedoc "Log level"
  @type log_level :: :debug | :info | :warn | :error

  @typedoc "Log metadata"
  @type log_metadata :: keyword()

  @doc """
  Safely executes a function with timeout and retry logic.

  ## Options
    * `:timeout` - Maximum time in milliseconds to wait for each attempt (default: 5000)
    * `:retries` - Number of retry attempts (default: 3)
    * `:backoff_base` - Base time in milliseconds for backoff calculation (default: 100)
    * `:backoff_type` - Type of backoff, either :exponential or :linear (default: :exponential)
  """
  @spec safely_execute((-> result), retry_opts()) :: {:ok, result} | {:error, term()}
        when result: term()
  def safely_execute(fun, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 5_000)
    retries = Keyword.get(opts, :retries, 3)
    backoff_base = Keyword.get(opts, :backoff_base, 100)
    backoff_type = Keyword.get(opts, :backoff_type, :exponential)

    do_safely_execute(fun, retries, timeout, backoff_base, backoff_type)
  end

  @spec do_safely_execute((-> term()), integer(), integer(), integer(), :exponential | :linear) ::
          {:ok, term()} | {:error, term()}
  defp do_safely_execute(_fun, retries, _timeout, _backoff_base, _backoff_type)
       when retries < 0 do
    {:error, :max_retries_reached}
  end

  defp do_safely_execute(fun, retries, timeout, backoff_base, backoff_type) do
    try do
      Task.await(Task.async(fun), timeout)
    rescue
      error ->
        Logger.warning("Execution failed: #{inspect(error)}. Retries left: #{retries}")
        backoff = calculate_backoff(retries, backoff_base, backoff_type)
        Process.sleep(backoff)
        do_safely_execute(fun, retries - 1, timeout, backoff_base, backoff_type)
    catch
      :exit, {:timeout, _} ->
        Logger.warning("Execution timed out. Retries left: #{retries}")
        backoff = calculate_backoff(retries, backoff_base, backoff_type)
        Process.sleep(backoff)
        do_safely_execute(fun, retries - 1, timeout, backoff_base, backoff_type)
    end
  end

  @spec calculate_backoff(non_neg_integer(), non_neg_integer(), :exponential | :linear) ::
          non_neg_integer()
  defp calculate_backoff(retry_count, base, :exponential) do
    trunc(base * :math.pow(2, retry_count))
  end

  defp calculate_backoff(retry_count, base, :linear) do
    base * (retry_count + 1)
  end

  @doc """
  Validates a map against a schema of required and optional keys.
  """
  @spec validate_schema(map(), schema_opts()) :: :ok | {:error, term()}
  def validate_schema(map, schema) do
    required_keys = Keyword.get(schema, :required, [])
    optional_keys = Keyword.get(schema, :optional, [])
    all_valid_keys = required_keys ++ optional_keys

    with :ok <- validate_required_keys(map, required_keys),
         :ok <- validate_unknown_keys(map, all_valid_keys) do
      :ok
    end
  end

  @spec validate_required_keys(map(), [atom()]) ::
          :ok | {:error, {:missing_required_keys, [atom()]}}
  defp validate_required_keys(map, required_keys) do
    missing_keys = Enum.filter(required_keys, &(not Map.has_key?(map, &1)))

    case missing_keys do
      [] -> :ok
      missing -> {:error, {:missing_required_keys, missing}}
    end
  end

  @spec validate_unknown_keys(map(), [atom()]) :: :ok | {:error, {:unknown_keys, [atom()]}}
  defp validate_unknown_keys(map, valid_keys) do
    unknown_keys = Enum.filter(Map.keys(map), &(&1 not in valid_keys))

    case unknown_keys do
      [] -> :ok
      unknown -> {:error, {:unknown_keys, unknown}}
    end
  end

  @doc """
  Formats an error tuple into a standardized error structure.
  """
  @spec format_error(term()) :: Error.AgentError.t()
  def format_error({:error, reason}) when is_binary(reason) do
    Error.AgentError.exception(message: reason, reason: :unknown)
  end

  def format_error({:error, reason}) do
    Error.AgentError.exception(
      message: "An error occurred: #{inspect(reason)}",
      reason: reason
    )
  end

  def format_error(%{__exception__: true} = error) do
    Error.AgentError.exception(
      message: Exception.message(error),
      reason:
        error.__struct__
        |> Module.split()
        |> List.last()
        |> Macro.underscore()
        |> String.to_atom()
    )
  end

  def format_error(error) do
    Error.AgentError.exception(
      message: "Unexpected error: #{inspect(error)}",
      reason: :unknown
    )
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
    try do
      {:ok, Jason.encode!(term)}
    rescue
      Protocol.UndefinedError ->
        {:error, :unserializable_term}

      Jason.EncodeError ->
        {:error, :invalid_json}

      error ->
        {:error, error}
    end
  end

  @doc """
  Deserializes a string back into a term.
  """
  @spec deserialize(String.t()) :: {:ok, term()} | {:error, term()}
  def deserialize(string) when is_binary(string) do
    try do
      {:ok, Jason.decode!(string, keys: :atoms)}
    rescue
      Jason.DecodeError ->
        {:error, :invalid_json}

      error ->
        {:error, error}
    end
  end

  def deserialize(_), do: {:error, :invalid_input}

  @doc """
  Logs a message with additional context and metadata.
  """
  @spec log(log_level(), String.t(), log_metadata()) :: :ok
  def log(level, message, metadata \\ []) do
    metadata = Keyword.merge([timestamp: DateTime.utc_now()], metadata)

    Logger.log(
      level,
      fn ->
        metadata_string =
          metadata
          |> Enum.map_join(" ", fn {k, v} -> "[#{k}=#{inspect(v)}]" end)

        "#{message} #{metadata_string}"
      end,
      metadata
    )
  end

  @doc """
  Deep merges two maps recursively.
  """
  @spec deep_merge(map(), map()) :: map()
  def deep_merge(left, right) when is_map(left) and is_map(right) do
    Map.merge(left, right, &deep_resolve/3)
  end

  @spec deep_resolve(term(), map(), map()) :: map()
  defp deep_resolve(_key, left, right) when is_map(left) and is_map(right) do
    deep_merge(left, right)
  end

  defp deep_resolve(_key, _left, right), do: right
end
