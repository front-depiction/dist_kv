defmodule DistKv.Permissions do
  @moduledoc """
  Manages permissions and whitelisted creators for the blockchain.

  This module maintains a mapping of creator fingerprints to their identities
  and public keys. Only whitelisted creators are allowed to submit transactions.
  """

  use GenServer
  require Logger

  @name __MODULE__

  # Configuration: hardcoded for now, could be loaded from file/env later
  @default_allowed %{
                     # Example entries - these would be real fingerprints in production
                     # "abc123..." => %{name: "node_a", public_key: ...}
                   }

  ## Public API

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, @default_allowed, name: @name)
  end

  @doc """
  Check if a creator (fingerprint) is allowed to submit transactions.
  """
  def allowed?(creator) when is_binary(creator) do
    GenServer.call(@name, {:allowed?, creator})
  end

  @doc """
  Get the public key for a given creator fingerprint.
  Returns {:ok, public_key} or :not_found.
  """
  def public_key_for(creator) when is_binary(creator) do
    GenServer.call(@name, {:public_key_for, creator})
  end

  @doc """
  Add a new allowed creator with their public key.
  This is an administrative function.
  """
  def add_creator(fingerprint, name, public_key) when is_binary(fingerprint) do
    GenServer.call(@name, {:add_creator, fingerprint, name, public_key})
  end

  @doc """
  Remove a creator from the allowed list.
  This is an administrative function.
  """
  def remove_creator(fingerprint) when is_binary(fingerprint) do
    GenServer.call(@name, {:remove_creator, fingerprint})
  end

  @doc """
  List all allowed creators.
  """
  def list_creators do
    GenServer.call(@name, :list_creators)
  end

  @doc """
  Verify a transaction's creator and signature.
  Returns :ok if valid, {:error, reason} otherwise.
  """
  def verify_transaction(%DistKv.Transaction{} = tx) do
    with true <- allowed?(tx.creator),
         {:ok, pub_key} <- public_key_for(tx.creator),
         true <- DistKv.Transaction.verify(tx, pub_key) do
      :ok
    else
      false when tx.creator ->
        {:error, :creator_not_allowed}

      :not_found ->
        {:error, :creator_not_found}

      false ->
        {:error, :invalid_signature}

      error ->
        {:error, error}
    end
  end

  @doc """
  Convenience function to create and register a new keypair.
  Returns {fingerprint, {public_key, private_key}}.
  """
  def create_and_register_keypair(name) do
    {pub_key, priv_key} = DistKv.Crypto.generate_keypair()
    fingerprint = DistKv.Crypto.public_key_fingerprint(pub_key)

    case add_creator(fingerprint, name, pub_key) do
      :ok -> {fingerprint, {pub_key, priv_key}}
      error -> error
    end
  end

  ## GenServer Callbacks

  def init(allowed_creators) do
    Logger.info("Starting Permissions with #{map_size(allowed_creators)} allowed creators")
    {:ok, allowed_creators}
  end

  def handle_call({:allowed?, creator}, _from, state) do
    result = Map.has_key?(state, creator)
    {:reply, result, state}
  end

  def handle_call({:public_key_for, creator}, _from, state) do
    result =
      case Map.get(state, creator) do
        nil -> :not_found
        %{public_key: pub_key} -> {:ok, pub_key}
      end

    {:reply, result, state}
  end

  def handle_call({:add_creator, fingerprint, name, public_key}, _from, state) do
    # Verify the fingerprint matches the public key
    computed_fingerprint = DistKv.Crypto.public_key_fingerprint(public_key)

    if computed_fingerprint == fingerprint do
      new_state = Map.put(state, fingerprint, %{name: name, public_key: public_key})
      Logger.info("Added creator: #{name} (#{fingerprint})")
      {:reply, :ok, new_state}
    else
      Logger.warning("Fingerprint mismatch when adding creator #{name}")
      {:reply, {:error, :fingerprint_mismatch}, state}
    end
  end

  def handle_call({:remove_creator, fingerprint}, _from, state) do
    case Map.get(state, fingerprint) do
      nil ->
        {:reply, {:error, :not_found}, state}

      %{name: name} ->
        new_state = Map.delete(state, fingerprint)
        Logger.info("Removed creator: #{name} (#{fingerprint})")
        {:reply, :ok, new_state}
    end
  end

  def handle_call(:list_creators, _from, state) do
    creators =
      Enum.map(state, fn {fingerprint, %{name: name}} ->
        %{fingerprint: fingerprint, name: name}
      end)

    {:reply, creators, state}
  end

  ## Helper Functions

  @doc """
  Load creators from a configuration file.
  Expected format: JSON with creator entries.
  """
  def load_from_file(path) do
    case File.read(path) do
      {:ok, content} ->
        case Jason.decode(content) do
          {:ok, data} -> parse_creators_config(data)
          {:error, reason} -> {:error, {:json_decode, reason}}
        end

      {:error, reason} ->
        {:error, {:file_read, reason}}
    end
  end

  defp parse_creators_config(%{"creators" => creators}) when is_list(creators) do
    parsed =
      Enum.reduce_while(creators, %{}, fn creator, acc ->
        case parse_creator_entry(creator) do
          {:ok, fingerprint, entry} -> {:cont, Map.put(acc, fingerprint, entry)}
          {:error, _} = error -> {:halt, error}
        end
      end)

    case parsed do
      %{} = result -> {:ok, result}
      error -> error
    end
  end

  defp parse_creators_config(_), do: {:error, :invalid_format}

  defp parse_creator_entry(%{
         "fingerprint" => fingerprint,
         "name" => name,
         "public_key" => pub_key_pem
       }) do
    try do
      # Parse PEM-encoded public key
      [{:SubjectPublicKeyInfo, der, _}] = :public_key.pem_decode(pub_key_pem)
      public_key = :public_key.der_decode(:SubjectPublicKeyInfo, der)

      # Verify fingerprint
      computed = DistKv.Crypto.public_key_fingerprint(public_key)

      if computed == fingerprint do
        {:ok, fingerprint, %{name: name, public_key: public_key}}
      else
        {:error, {:fingerprint_mismatch, fingerprint}}
      end
    rescue
      e -> {:error, {:parse_error, e}}
    end
  end

  defp parse_creator_entry(_), do: {:error, :invalid_creator_entry}
end
