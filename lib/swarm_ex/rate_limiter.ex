defmodule SwarmEx.RateLimiter do
  @moduledoc """
  Rate limiter implementation using a token bucket algorithm.
  Handles rate limiting for agent message passing.
  """

  use GenServer
  require Logger

  @type t :: %__MODULE__{
          rate_limit: pos_integer(),
          tokens: float(),
          last_update: integer(),
          max_tokens: pos_integer()
        }

  defstruct rate_limit: 100,
            tokens: 100.0,
            last_update: 0,
            max_tokens: 100

  # Client API

  @doc """
  Starts a new rate limiter process.

  ## Options
    * :rate_limit - Tokens per second (default: 100)
    * :max_tokens - Maximum token bucket size (default: same as rate_limit)
    * :name - Optional name for registration
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: opts[:name])
  end

  @doc """
  Checks if an operation can proceed under the rate limit.
  Returns :ok if allowed, or {:error, wait_time} with milliseconds to wait.
  """
  @spec check_limit(GenServer.server()) :: :ok | {:error, pos_integer()}
  def check_limit(pid) do
    GenServer.call(pid, :check_limit)
  end

  @doc """
  Gets current rate limiter stats.
  """
  @spec get_stats(GenServer.server()) :: {:ok, map()}
  def get_stats(pid) do
    GenServer.call(pid, :get_stats)
  end

  # Server Callbacks

  @impl true
  def init(opts) do
    rate_limit = opts[:rate_limit] || 100
    max_tokens = opts[:max_tokens] || rate_limit

    state = %__MODULE__{
      rate_limit: rate_limit,
      tokens: max_tokens,
      last_update: System.monotonic_time(:millisecond),
      max_tokens: max_tokens
    }

    Logger.debug(%{
      event_type: "system_status",
      telemetry_event: "rate_limiter_started",
      rate_limit: rate_limit,
      max_tokens: max_tokens
    })

    {:ok, state}
  end

  @impl true
  def handle_call(:check_limit, _from, state) do
    now = System.monotonic_time(:millisecond)
    time_passed = now - state.last_update

    new_tokens =
      min(
        state.max_tokens,
        state.tokens + time_passed * (state.rate_limit / 1000)
      )

    cond do
      new_tokens >= 1.0 ->
        {:reply, :ok, %{state | tokens: new_tokens - 1, last_update: now}}

      new_tokens < 1.0 ->
        # Calculate wait time in ms before next token is available
        wait_time = trunc((1 - new_tokens) * (1000 / state.rate_limit))
        {:reply, {:error, wait_time}, %{state | tokens: new_tokens, last_update: now}}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = %{
      available_tokens: state.tokens,
      rate_limit: state.rate_limit,
      max_tokens: state.max_tokens,
      last_update: state.last_update
    }

    {:reply, {:ok, stats}, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warning(%{
      event_type: "system_status",
      telemetry_event: "unexpected_message",
      message: inspect(msg)
    })

    {:noreply, state}
  end
end
