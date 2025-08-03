defmodule DistKv.Transaction do
  @moduledoc """
  Represents a cryptographically signed transaction.
  Each transaction is an atomic operation with metadata and a signature.
  """

  @enforce_keys [:id, :operation, :timestamp, :creator, :signature]
  defstruct [:id, :operation, :timestamp, :creator, :signature]

  @type operation :: {:put, key :: binary(), value :: binary()} | {:delete, key :: binary()}
  @type t :: %__MODULE__{
          id: binary(),
          operation: operation(),
          timestamp: integer(),
          creator: binary(),
          signature: binary()
        }

  @doc """
  Create a new signed transaction.

  ## Parameters
  - operation: The operation to perform ({:put, key, value} or {:delete, key})
  - creator: The public key fingerprint of the creator
  - priv_key: The private key to sign with

  ## Returns
  A signed Transaction struct
  """
  def new(operation, creator, priv_key) do
    timestamp = System.system_time(:millisecond)
    id = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)

    to_sign =
      canonicalize(%{
        id: id,
        operation: operation,
        timestamp: timestamp,
        creator: creator
      })

    signature = DistKv.Crypto.sign(to_sign, priv_key)

    %__MODULE__{
      id: id,
      operation: operation,
      timestamp: timestamp,
      creator: creator,
      signature: signature
    }
  end

  @doc """
  Verify the signature of a transaction against a public key.

  ## Parameters
  - tx: The transaction to verify
  - pub_key: The public key to verify against

  ## Returns
  true if the signature is valid, false otherwise
  """
  def verify(%__MODULE__{} = tx, pub_key) do
    to_verify =
      canonicalize(%{
        id: tx.id,
        operation: tx.operation,
        timestamp: tx.timestamp,
        creator: tx.creator
      })

    DistKv.Crypto.verify(to_verify, tx.signature, pub_key)
  end

  @doc """
  Check if a transaction is well-formed and has valid structure.
  """
  def valid_structure?(%__MODULE__{} = tx) do
    case tx do
      %{id: id, operation: op, timestamp: ts, creator: creator, signature: sig}
      when is_binary(id) and is_integer(ts) and is_binary(creator) and is_binary(sig) ->
        valid_operation?(op)

      _ ->
        false
    end
  end

  @doc """
  Get a hash of the transaction for inclusion in merkle trees.
  """
  def hash(%__MODULE__{} = tx) do
    tx
    |> :erlang.term_to_binary()
    |> then(&:crypto.hash(:sha256, &1))
  end

  @doc """
  Convert transaction to JSON-serializable format.
  """
  def to_json(%__MODULE__{} = tx) do
    %{
      id: tx.id,
      operation: operation_to_json(tx.operation),
      timestamp: tx.timestamp,
      creator: tx.creator,
      signature: Base.encode64(tx.signature)
    }
  end

  @doc """
  Convert from JSON format back to Transaction struct.
  """
  def from_json(%{
        "id" => id,
        "operation" => operation,
        "timestamp" => timestamp,
        "creator" => creator,
        "signature" => signature
      }) do
    %__MODULE__{
      id: id,
      operation: operation_from_json(operation),
      timestamp: timestamp,
      creator: creator,
      signature: Base.decode64!(signature)
    }
  end

  def from_json(%{
        id: id,
        operation: operation,
        timestamp: timestamp,
        creator: creator,
        signature: signature
      }) do
    %__MODULE__{
      id: id,
      operation: operation_from_json(operation),
      timestamp: timestamp,
      creator: creator,
      signature: Base.decode64!(signature)
    }
  end

  # Private functions

  defp canonicalize(map) do
    # Create deterministic representation for signing
    map
    |> Enum.sort()
    |> :erlang.term_to_binary()
  end

  defp valid_operation?({:put, key, value}) when is_binary(key) and is_binary(value), do: true
  defp valid_operation?({:delete, key}) when is_binary(key), do: true
  defp valid_operation?(_), do: false

  defp operation_to_json({:put, key, value}) do
    %{"type" => "put", "key" => key, "value" => value}
  end

  defp operation_to_json({:delete, key}) do
    %{"type" => "delete", "key" => key}
  end

  defp operation_from_json(%{"type" => "put", "key" => key, "value" => value}) do
    {:put, key, value}
  end

  defp operation_from_json(%{"type" => "delete", "key" => key}) do
    {:delete, key}
  end

  defp operation_from_json(%{"key" => key, "type" => "put", "value" => value}) do
    {:put, key, value}
  end

  defp operation_from_json(%{"key" => key, "type" => "delete"}) do
    {:delete, key}
  end
end
