defmodule DistKv.Phase1Demo do
  @moduledoc """
  Demonstration of Phase 1 blockchain functionality:
  - Key generation and fingerprinting
  - Transaction creation and signing
  - Permission management
  - Transaction verification
  """

  require Logger

  @doc """
  Run a complete demonstration of Phase 1 functionality.
  """
  def run_demo do
    Logger.info("=== Phase 1 Blockchain Demo ===")

    # Step 1: Generate keypairs for two users
    Logger.info("1. Generating keypairs for users...")
    {alice_fingerprint, {alice_pub, alice_priv}} = generate_user_keypair("Alice")
    {bob_fingerprint, {bob_pub, bob_priv}} = generate_user_keypair("Bob")

    # Step 2: Register users in permissions system
    Logger.info("2. Registering users in permissions system...")
    :ok = DistKv.Permissions.add_creator(alice_fingerprint, "Alice", alice_pub)
    :ok = DistKv.Permissions.add_creator(bob_fingerprint, "Bob", bob_pub)

    # Step 3: Create and verify transactions
    Logger.info("3. Creating signed transactions...")

    # Alice creates a put transaction
    alice_tx =
      DistKv.Transaction.new(
        {:put, "greeting", "Hello from Alice!"},
        alice_fingerprint,
        alice_priv
      )

    # Bob creates a put transaction
    bob_tx =
      DistKv.Transaction.new(
        {:put, "counter", "42"},
        bob_fingerprint,
        bob_priv
      )

    # Step 4: Verify transactions
    Logger.info("4. Verifying transactions...")
    verify_transaction(alice_tx, "Alice")
    verify_transaction(bob_tx, "Bob")

    # Step 5: Try invalid transaction from unknown user
    Logger.info("5. Testing rejection of unauthorized transaction...")
    {unknown_pub, unknown_priv} = DistKv.Crypto.generate_keypair()
    unknown_fingerprint = DistKv.Crypto.public_key_fingerprint(unknown_pub)

    unauthorized_tx =
      DistKv.Transaction.new(
        {:put, "hack", "malicious_value"},
        unknown_fingerprint,
        unknown_priv
      )

    verify_transaction(unauthorized_tx, "Unknown User")

    # Step 6: Test JSON serialization
    Logger.info("6. Testing JSON serialization...")
    test_json_serialization(alice_tx)

    # Step 7: Show current permissions
    Logger.info("7. Current authorized creators:")
    list_creators()

    Logger.info("=== Demo Complete ===")
  end

  @spec generate_user_keypair(any()) ::
          {binary(),
           {binary() | [binary() | byte()],
            binary()
            | [binary() | integer()]
            | integer()
            | {binary() | integer(), binary() | integer()}}}
  @doc """
  Generate a keypair and return fingerprint with keys.
  """
  def generate_user_keypair(name) do
    {pub_key, priv_key} = DistKv.Crypto.generate_keypair()
    fingerprint = DistKv.Crypto.public_key_fingerprint(pub_key)

    Logger.info("Generated keypair for #{name}: #{fingerprint}")

    {fingerprint, {pub_key, priv_key}}
  end

  @doc """
  Verify a transaction and log the result.
  """
  def verify_transaction(tx, user_name) do
    case DistKv.Permissions.verify_transaction(tx) do
      :ok ->
        Logger.info("✓ #{user_name}'s transaction verified successfully")
        Logger.info("  Transaction ID: #{tx.id}")
        Logger.info("  Operation: #{inspect(tx.operation)}")

      {:error, reason} ->
        Logger.warning("✗ #{user_name}'s transaction rejected: #{reason}")
        Logger.warning("  Transaction ID: #{tx.id}")
        Logger.warning("  Creator: #{tx.creator}")
    end
  end

  @doc """
  Test JSON serialization round-trip.
  """
  def test_json_serialization(tx) do
    json_data = DistKv.Transaction.to_json(tx)
    Logger.info("Transaction as JSON: #{Jason.encode!(json_data)}")

    reconstructed_tx = DistKv.Transaction.from_json(json_data)

    if tx.id == reconstructed_tx.id and tx.operation == reconstructed_tx.operation do
      Logger.info("✓ JSON serialization round-trip successful")
    else
      Logger.error("✗ JSON serialization round-trip failed")
    end
  end

  @doc """
  List all currently authorized creators.
  """
  def list_creators do
    creators = DistKv.Permissions.list_creators()

    Enum.each(creators, fn %{name: name, fingerprint: fingerprint} ->
      Logger.info("  - #{name}: #{fingerprint}")
    end)
  end

  @doc """
  Create a simple blockchain with a few transactions to demonstrate ordering.
  """
  def create_sample_chain do
    Logger.info("=== Creating Sample Transaction Chain ===")

    # Generate and register a user
    {fingerprint, {_pub, priv}} = DistKv.Permissions.create_and_register_keypair("ChainUser")

    # Create a sequence of transactions
    transactions = [
      DistKv.Transaction.new({:put, "step1", "initialize"}, fingerprint, priv),
      DistKv.Transaction.new({:put, "step2", "configure"}, fingerprint, priv),
      DistKv.Transaction.new({:put, "step3", "execute"}, fingerprint, priv),
      DistKv.Transaction.new({:delete, "step1"}, fingerprint, priv)
    ]

    # Verify all transactions
    Enum.with_index(transactions, 1)
    |> Enum.each(fn {tx, index} ->
      case DistKv.Permissions.verify_transaction(tx) do
        :ok -> Logger.info("Transaction #{index}: ✓ verified")
        error -> Logger.error("Transaction #{index}: ✗ #{inspect(error)}")
      end
    end)

    Logger.info("Created chain with #{length(transactions)} transactions")
    transactions
  end

  @doc """
  Utility to show transaction hashes (useful for merkle trees later).
  """
  def show_transaction_hashes(transactions) do
    Logger.info("Transaction hashes:")

    Enum.with_index(transactions, 1)
    |> Enum.each(fn {tx, index} ->
      hash = DistKv.Transaction.hash(tx) |> Base.encode16(case: :lower)
      Logger.info("  #{index}. #{hash}")
    end)
  end
end
