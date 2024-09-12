#!/usr/bin/env bash

rm -rf $HOME/.minid

MINID_BIN=$(which minid)
if [ -z "$MINID_BIN" ]; then
    GOBIN=$(go env GOPATH)/bin
    MINID_BIN=$(which $GOBIN/minid)
fi

if [ -z "$MINID_BIN" ]; then
    echo "please verify minid is installed"
    exit 1
fi

# configure minid
# $MINID_BIN config set client chain-id demo
# $MINID_BIN config set client keyring-backend test

# Supported Algorithms: Dilithium2, Dilithium3, Dilithium5
ALGORITHM=$(echo 'Dilithium2')

$MINID_BIN gen-pqc-key $ALGORITHM --name alice
$MINID_BIN gen-pqc-key $ALGORITHM --name bob

echo ""
echo ""
echo ""

# Serialize a test transaction from Alice to Bob
TX=$(echo '{"from":"alice","to":"bob","amount":100,"nonce":1}')
echo "Serializing test transaction 1: $TX"
TX_BYTES=$(echo '{"from":"alice","to":"bob","amount":100,"nonce":1}' | base64)
# TX_BYTES=$(echo 'testing' | base64)
echo "Transaction serialized: $TX_BYTES"

# Sign the transaction using Alice's private key
echo "Signing the transaction with Alice's private key..."
SIGNATURE=$($MINID_BIN sign-tx $ALGORITHM $TX_BYTES --privkey ./alice_private.key)
echo "Transaction signed: $SIGNATURE"

# Verify the transaction signature using Alice's public key
echo "Verifying the transaction signature..."
VALID=$($MINID_BIN verify-tx-signature $ALGORITHM $TX_BYTES $SIGNATURE --pubkey ./alice_public.key)

# Output the result of the verification
if [ "$VALID" = "true" ]; then
    echo "Transaction 1 signature is valid!"
else
    echo "Transaction 1 signature is invalid!"
fi

echo ""
echo ""
echo ""

# Serialize a test transaction from Alice to Bob
TX=$(echo '{"from":"bob","to":"alice","amount":100,"nonce":2}')
echo "Serializing test transaction 2: $TX"
TX_BYTES=$(echo '{"from":"bob","to":"alice","amount":100,"nonce":2}' | base64)
# TX_BYTES=$(echo 'testing' | base64)
echo "Transaction serialized: $TX_BYTES"

# Sign the transaction using Alice's private key
echo "Signing the transaction with Bob's private key..."
SIGNATURE=$($MINID_BIN sign-tx $ALGORITHM $TX_BYTES --privkey ./bob_private.key)
echo "Transaction signed: $SIGNATURE"

# Verify the transaction signature using Alice's public key
echo "Verifying the transaction signature..."
VALID=$($MINID_BIN verify-tx-signature $ALGORITHM $TX_BYTES $SIGNATURE --pubkey ./bob_public.key)

# Output the result of the verification
if [ "$VALID" = "true" ]; then
    echo "Transaction 2 signature is valid!"
else
    echo "Transaction 2 signature is invalid!"
fi


# $MINID_BIN keys add alice
# $MINID_BIN keys add bob

# $MINID_BIN init test --chain-id demo --default-denom mini

# # update genesis
# $MINID_BIN genesis add-genesis-account alice 10000000mini --keyring-backend test
# $MINID_BIN genesis add-genesis-account bob 1000mini --keyring-backend test

# # create default validator
# $MINID_BIN genesis gentx alice 1000000mini --chain-id demo
# $MINID_BIN genesis collect-gentxs
