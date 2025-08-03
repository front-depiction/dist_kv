defmodule DistKv.Crypto do
  @moduledoc """
  Cryptographic utilities for signing and verifying transactions.
  Uses ECDSA P-256 for simplicity and compatibility with standard libraries.
  """

  @hash_algo :sha256

  @doc """
  Generate an EC keypair (P-256).
  Returns a tuple {public_key, private_key}.
  """
  def generate_keypair do
    # Use the newer OTP format for key generation
    :crypto.generate_key(:ecdh, :secp256r1)
  end

  @doc """
  Sign a message with a private key.
  Returns the signature as binary.
  """
  def sign(message, priv_key) when is_binary(message) do
    # Use crypto module for simpler ECDSA signing
    :crypto.sign(:ecdsa, @hash_algo, message, [priv_key, :secp256r1])
  end

  @doc """
  Verify a signature against a message and public key.
  Returns true if valid, false otherwise.
  """
  def verify(message, signature, pub_key) when is_binary(message) do
    try do
      :crypto.verify(:ecdsa, @hash_algo, message, signature, [pub_key, :secp256r1])
    rescue
      _ -> false
    end
  end

  @doc """
  Create a cryptographic digest of an Elixir term.
  Converts the term to binary representation first.
  """
  def digest(term) do
    term
    |> :erlang.term_to_binary()
    |> :crypto.hash(@hash_algo)
  end

  @doc """
  Convert a public key to a fingerprint (base16 encoded hash).
  This is used as the identity/creator field in transactions.
  """
  def public_key_fingerprint(pub_key) do
    # For the simplified version, just hash the public key directly
    # In a production system, you'd want proper DER encoding
    :crypto.hash(@hash_algo, pub_key)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Convert a keypair to a fingerprint for convenience.
  """
  def keypair_fingerprint({pub_key, _priv_key}) do
    public_key_fingerprint(pub_key)
  end
end
