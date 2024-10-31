defmodule SwarmEx.Tool do
  @moduledoc """
  DEPRECATED: This module is deprecated. Tools should be implemented as regular modules with functions instead.

  ## Migration Guide

  Instead of using the Tool behavior, define your tools as regular modules with functions:

  ### Before:

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

  ### After:

      defmodule MyTool do
        def process(args) do
          # Validate args if needed
          with :ok <- validate_args(args),
               {:ok, result} <- do_process(args) do
            cleanup(args)
            {:ok, result}
          end
        end

        defp validate_args(args) do
          # Optional validation
          :ok
        end

        defp do_process(args) do
          # Main processing logic
          {:ok, result}
        end

        defp cleanup(args) do
          # Optional cleanup
          :ok
        end
      end

  The new approach:
  - Is simpler and more idiomatic Elixir
  - Gives more flexibility in function naming and implementation
  - Allows for better integration with other libraries
  - Reduces boilerplate code
  - Makes testing easier
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
  DEPRECATED: Use direct function calls instead.

  Safely executes a tool with the given arguments and options.

  ## Options
    * `:timeout` - Maximum time in milliseconds to wait (default: 5000)
    * `:retries` - Number of retry attempts (default: 3)
    * `:validate_args` - Whether to validate arguments (default: true)
  """
  @deprecated "Tools should be implemented as regular modules with functions"
  @spec execute(t(), args(), options()) :: result()
  def execute(tool, args, opts \\ []) do
    require Logger
    Logger.warning("SwarmEx.Tool.execute/3 is deprecated. Use direct function calls instead.")

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
  DEPRECATED: Use regular module definition instead.

  Validates that a module implements the Tool behavior correctly.
  """
  @deprecated "Tools should be implemented as regular modules with functions"
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

  @doc """
  DEPRECATED: Use regular module configuration instead.

  Registers a tool configuration in the runtime.
  """
  @deprecated "Tools should be implemented as regular modules with functions"
  @spec register(t(), keyword()) :: :ok | {:error, term()}
  def register(tool, config \\ []) when is_atom(tool) and is_list(config) do
    require Logger

    Logger.warning(
      "SwarmEx.Tool.register/2 is deprecated. Use regular module configuration instead."
    )

    with :ok <- validate_tool(tool),
         :ok <- validate_config(config) do
      :persistent_term.put({__MODULE__, tool}, config)
      :ok
    end
  end

  @doc """
  DEPRECATED: Use regular module configuration instead.

  Retrieves the configuration for a registered tool.
  """
  @deprecated "Tools should be implemented as regular modules with functions"
  @spec get_config(t()) :: {:ok, keyword()} | {:error, term()}
  def get_config(tool) when is_atom(tool) do
    require Logger

    Logger.warning(
      "SwarmEx.Tool.get_config/1 is deprecated. Use regular module configuration instead."
    )

    case :persistent_term.get({__MODULE__, tool}, :not_found) do
      :not_found -> {:error, :not_registered}
      config -> {:ok, config}
    end
  end

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
