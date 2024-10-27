defmodule SwarmEx.Tool do
  @moduledoc """
  Defines the behavior and functionality for agent tools.

  Tools are capabilities that agents can use to perform specific tasks. Each tool
  must implement this behavior to be usable within the SwarmEx system.

  ## Tool Configuration

  Tools can be configured with the following options:
    * `:timeout` - Maximum time in milliseconds to wait for tool execution (default: 5000)
    * `:retries` - Number of retry attempts for failed executions (default: 3)
    * `:validate_args` - Whether to validate arguments before execution (default: true)

  ## Example

      defmodule MyTool do
        @behaviour SwarmEx.Tool

        @impl true
        def execute(args) do
          # Perform tool operation
          {:ok, result}
        end

        @impl true
        def validate(args) do
          # Validate incoming arguments
          :ok
        end

        @impl true
        def cleanup(args) do
          # Cleanup any resources
          :ok
        end
      end
  """

  require Logger
  alias SwarmEx.{Error, Utils}

  @type t :: module()
  @type args :: term()
  @type result :: {:ok, term()} | {:error, term()}
  @type validation_result :: :ok | {:error, term()}
  @type cleanup_result :: :ok | {:error, term()}
  @type options :: [
          timeout: non_neg_integer(),
          retries: non_neg_integer(),
          validate_args: boolean()
        ]

  # Required callbacks
  @callback execute(args()) :: result()
  @callback validate(args()) :: validation_result()
  @callback cleanup(args()) :: cleanup_result()

  @doc """
  Safely executes a tool with the given arguments and options.

  ## Options
    * `:timeout` - Maximum time in milliseconds to wait (default: 5000)
    * `:retries` - Number of retry attempts (default: 3)
    * `:validate_args` - Whether to validate arguments (default: true)

  ## Examples

      iex> SwarmEx.Tool.execute(MyTool, args, timeout: 10_000)
      {:ok, result}

      iex> SwarmEx.Tool.execute(InvalidTool, bad_args)
      {:error, :validation_failed}
  """
  @spec execute(t(), args(), options()) :: result()
  def execute(tool, args, opts \\ []) do
    opts = normalize_options(opts)

    with :ok <- validate_tool(tool),
         :ok <- maybe_validate_args(tool, args, opts),
         {:ok, result} <- do_execute(tool, args, opts) do
      {:ok, result}
    else
      {:error, reason} = error ->
        Logger.error("Tool execution failed: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Validates that a module implements the Tool behavior correctly.

  Returns `:ok` if the tool is valid, `{:error, reason}` otherwise.

  ## Examples

      iex> SwarmEx.Tool.validate_tool(MyTool)
      :ok

      iex> SwarmEx.Tool.validate_tool(InvalidModule)
      {:error, :invalid_tool}
  """
  @spec validate_tool(t()) :: :ok | {:error, term()}
  def validate_tool(tool) when is_atom(tool) do
    required_callbacks = [:execute, :validate, :cleanup]

    missing_callbacks =
      Enum.filter(required_callbacks, fn callback ->
        not function_exported?(tool, callback, 1)
      end)

    case missing_callbacks do
      [] -> :ok
      missing -> {:error, {:missing_callbacks, missing}}
    end
  end

  def validate_tool(_), do: {:error, :invalid_tool}

  # Private Functions

  defp normalize_options(opts) do
    Keyword.merge(
      [
        timeout: 5_000,
        retries: 3,
        validate_args: true
      ],
      opts
    )
  end

  defp maybe_validate_args(tool, args, opts) do
    if opts[:validate_args] do
      case tool.validate(args) do
        :ok -> :ok
        {:error, reason} -> {:error, {:validation_failed, reason}}
        other -> {:error, {:invalid_validation_result, other}}
      end
    else
      :ok
    end
  end

  defp do_execute(tool, args, opts) do
    Utils.safely_execute(
      fn -> tool.execute(args) end,
      timeout: opts[:timeout],
      retries: opts[:retries]
    )
  after
    # Always attempt cleanup, but don't fail if it errors
    try do
      tool.cleanup(args)
    rescue
      e ->
        Logger.warning("Tool cleanup failed: #{inspect(e)}")
        :ok
    end
  end

  @doc """
  Registers a tool configuration in the runtime.
  This allows for dynamic tool configuration and validation.

  ## Examples

      iex> SwarmEx.Tool.register(MyTool, max_retries: 5)
      :ok
  """
  @spec register(t(), keyword()) :: :ok | {:error, term()}
  def register(tool, config \\ []) when is_atom(tool) and is_list(config) do
    with :ok <- validate_tool(tool),
         :ok <- validate_config(config) do
      # Store tool configuration in persistent term for fast access
      :persistent_term.put({__MODULE__, tool}, config)
      :ok
    end
  end

  @doc """
  Retrieves the configuration for a registered tool.

  ## Examples

      iex> SwarmEx.Tool.get_config(MyTool)
      {:ok, [max_retries: 5]}

      iex> SwarmEx.Tool.get_config(UnregisteredTool)
      {:error, :not_registered}
  """
  @spec get_config(t()) :: {:ok, keyword()} | {:error, term()}
  def get_config(tool) when is_atom(tool) do
    case :persistent_term.get({__MODULE__, tool}, :not_found) do
      :not_found -> {:error, :not_registered}
      config -> {:ok, config}
    end
  end

  defp validate_config(config) do
    schema = [
      max_retries: [type: :integer, required: false],
      timeout: [type: :integer, required: false],
      validate_args: [type: :boolean, required: false]
    ]

    case Utils.validate_schema(Map.new(config), required: [], optional: Keyword.keys(schema)) do
      :ok -> :ok
      {:error, reason} -> {:error, {:invalid_config, reason}}
    end
  end
end
