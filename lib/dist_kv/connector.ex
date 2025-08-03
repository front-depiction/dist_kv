defmodule DistKv.Connector do
  @moduledoc """
  Periodically attempts to connect to peer nodes over distributed Erlang.
  """
  use GenServer
  require Logger

  @retry_interval 3_000

  def start_link(peers) do
    GenServer.start_link(__MODULE__, peers, name: __MODULE__)
  end

  def init(peers) do
    schedule_tick()
    {:ok, peers}
  end

  def handle_info(:tick, peers) do
    Enum.each(peers, fn peer ->
      if peer != node() and not Enum.member?(Node.list(), peer) do
        case Node.connect(peer) do
          true -> Logger.info("Connected to #{peer}")
          false -> Logger.debug("Failed to connect to #{peer}")
          :ignored -> Logger.debug("Ignored connecting to #{peer}")
        end
      end
    end)

    schedule_tick()
    {:noreply, peers}
  end

  defp schedule_tick do
    Process.send_after(self(), :tick, @retry_interval)
  end
end
