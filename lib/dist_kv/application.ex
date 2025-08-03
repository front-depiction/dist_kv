defmodule DistKv.Application do
  use Application
  require Logger

  def start(_type, _args) do
    peers =
      System.get_env("PEERS", "")
      |> String.split(",", trim: true)
      |> Enum.map(&String.to_atom/1)

    children = [
      {DistKv.Connector, peers},
      DistKv.KVStore,
      DistKv.Permissions
    ]

    Logger.info("Starting distributed KV node #{node()} with peers #{inspect(peers)}")
    Supervisor.start_link(children, strategy: :one_for_one, name: DistKv.Supervisor)
  end
end
