defmodule DistKv.KVStore do
  @moduledoc """
  Simple in-memory last-write-wins distributed KV using Erlang distribution.
  """
  use GenServer
  require Logger

  @name __MODULE__

  # Public API

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, %{}, name: @name)
  end

  @doc "Put a key/value locally and broadcast to connected nodes."
  def put(key, value) do
    GenServer.cast(@name, {:local_put, key, value})
  end

  @doc "Get the current value for a key."
  def get(key) do
    case GenServer.call(@name, {:get, key}) do
      nil -> :not_found
      %{value: v} -> {:ok, v}
    end
  end

  @doc "Inspect full raw state."
  def state do
    GenServer.call(@name, :state)
  end

  # GenServer

  def init(_), do: {:ok, %{}}

  def handle_cast({:local_put, key, value}, state) do
    timestamp = System.system_time(:millisecond)
    entry = %{value: value, timestamp: timestamp, node: node()}
    new_state = merge_entry(state, key, entry)

    # Broadcast to all connected nodes
    Enum.each([node() | Node.list()], fn n ->
      unless n == node() do
        GenServer.cast({@name, n}, {:replicate_put, key, value, timestamp, node()})
      end
    end)

    {:noreply, new_state}
  end

  def handle_cast({:replicate_put, key, value, ts, origin_node}, state) do
    entry = %{value: value, timestamp: ts, node: origin_node}
    new_state = merge_entry(state, key, entry)
    {:noreply, new_state}
  end

  def handle_call({:get, key}, _from, state) do
    {:reply, Map.get(state, key), state}
  end

  def handle_call(:state, _from, state) do
    {:reply, state, state}
  end

  # Compare and merge: last-write-wins, tie-breaker by node name
  defp merge_entry(state, key, incoming) do
    updated =
      case Map.get(state, key) do
        nil ->
          incoming

        existing ->
          if newer?(incoming, existing), do: incoming, else: existing
      end

    Map.put(state, key, updated)
  end

  defp newer?(%{timestamp: ta, node: na}, %{timestamp: tb, node: nb}) do
    cond do
      ta > tb -> true
      ta < tb -> false
      ta == tb -> to_string(na) >= to_string(nb)
    end
  end
end
