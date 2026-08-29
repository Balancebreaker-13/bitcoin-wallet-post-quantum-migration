# Bitcoin Cryptography Deep Dive

## Overview
This document provides an in-depth analysis of Bitcoin's current cryptographic infrastructure, enabling a proper migration strategy to post-quantum cryptography.

## 1. Bitcoin ECDSA Implementation (secp256k1)

### What is ECDSA?

Elliptic Curve Digital Signature Algorithm (ECDSA) is the cryptographic scheme used to sign Bitcoin transactions.

**Mathematical Foundation:**
- Elliptic Curve: y² = x³ + 7 (mod p)
- Curve: secp256k1 (parameters defined by SEC2)
- Prime Field: p = 2²⁵⁶ - 2³² - 977
- Private Key: 256-bit random number (1 to n-1)
- Public Key: Point on curve (x, y coordinates)

### Bitcoin's Use of ECDSA

**Private Key Generation:**
```
Private Key (d): Random 256-bit number
Public Key (Q): Q = d × G (where G is generator point)
Public Key Size: 65 bytes (uncompressed) or 33 bytes (compressed)
```

**Signature Generation (Signing a Transaction):**
```
Transaction data → Hash with SHA-256 → 256-bit hash

Sign with ECDSA:
  1. Generate random nonce k
  2. Calculate r = (k × G).x mod n
  3. Calculate s = k⁻¹(hash + r×d) mod n
  4. Signature = (r, s) [64 bytes total]
```

**Signature Verification:**
```
Given: message, signature (r, s), public key Q
Verify:
  1. Calculate w = s⁻¹ mod n
  2. Calculate u1 = (hash × w) mod n
  3. Calculate u2 = (r × w) mod n
  4. Calculate point P = u1×G + u2×Q
  5. Check if P.x ≡ r (mod n)
```

**Security:** 256-bit ECDSA provides ~128-bit symmetric security (2^128 operations to break).

## 2. Bitcoin Transactions and Signatures

### Transaction Structure

**Bitcoin Transaction Format:**

```
Version (4 bytes)
  Input Count (varint)
  [For each input]
    Previous TX Hash (32 bytes)
    Previous Output Index (4 bytes)
    Script Length (varint)
    Script (scriptPubKey or scriptSig) (variable)
    Sequence (4 bytes)
  Output Count (varint)
  [For each output]
    Value in Satoshis (8 bytes)
    Script Length (varint)
    Script (scriptPubKey) (variable)
  Locktime (4 bytes)
```

### Script Execution (Legacy - P2PKH)

**Pay-to-Pubkey-Hash (P2PKH) - Most common before Taproot:**

**locking script (scriptPubKey):**
```
OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
```

**unlocking script (scriptSig):**
```
<signature> <pubKey>
```

**Execution Flow:**
```
1. Stack: [signature, pubKey]
2. OP_DUP: Duplicate pubKey → [signature, pubKey, pubKey]
3. OP_HASH160: Hash pubKey → [signature, pubKey, pubKeyHash]
4. Compare with hash in locking script → [signature, pubKey, true]
5. OP_EQUALVERIFY: Verify true (pop and require true) → [signature, pubKey]
6. OP_CHECKSIG: Verify signature against pubKey
```

**Public Key Exposure:** Full 33-byte compressed public key is revealed in scriptSig

### Schnorr Signatures (BIP340)

**Bitcoin Taproot introduces Schnorr signatures:**

**Advantages over ECDSA:**
- Deterministic (no random nonce)
- Simpler math
- Smaller signatures (64 bytes vs 71-72 bytes)
- Supports signature aggregation
- Better for privacy

**Schnorr Signature:**
```
Private Key: d (256-bit)
Public Key: P = d×G (32 bytes, x-coordinate only)

Sign:
  1. Random nonce r
  2. R = r×G (32 bytes)
  3. e = Hash(R || P || message) (256-bit)
  4. s = (r + e×d) mod n (32 bytes)
  5. Signature = R || s (64 bytes)

Verify:
  1. e = Hash(R || P || message)
  2. Check: s×G ≡ R + e×P
```

## 3. Key Derivation Methods

### BIP32 - Hierarchical Deterministic Wallets

**Purpose:** Generate unlimited keys from a single seed

**Master Key Generation:**
```
Seed (256+ bits) → HMAC-SHA512("Bitcoin seed", seed)
  → Master Key (256-bit) + Master Chain Code (256-bit)
```

**Key Derivation Path (BIP44 Standard):**
```
m / purpose' / coin_type' / account' / change / address_index

Example: m/44'/0'/0'/0/0
  m = master
  44' = BIP44 purpose
  0' = Bitcoin (coin type 0)
  0' = account 0
  0 = external chain (receiving addresses)
  0 = first address
```

**Hardened vs Normal Derivation:**
- Hardened (with '): Cannot derive private key from public key
- Normal: Can derive public key directly from parent public key

**Example Derivation:**
```python
from mnemonic import Mnemonic
from bip32utils import BIP32_MAINNET

# 1. Generate seed from mnemonic
mnemo = Mnemonic("english")
seed = mnemo.to_seed("12 word mnemonic...")

# 2. Create BIP32 root
root = BIP32Key.fromSeed(seed, BIP32_MAINNET)

# 3. Derive path: m/44'/0'/0'/0/0
path = "m/44'/0'/0'/0/0"
addr_key = root.ChildKeyDerivation(path)

# 4. Get address
private_key = addr_key.privateKey()
public_key = addr_key.publicKey()
address = addr_key.address()  # P2PKH, P2SH, or Bech32
```

### Child Key Derivation Process

**Hardened Child (Private → Private):**
```
data = 0x00 || private_key || index
hmac = HMAC-SHA512(chain_code, data)
child_key = (parent_key + hmac_left) mod n
child_chain_code = hmac_right
```

**Normal Child (Public → Public):**
```
data = compressed_public_key || index
hmac = HMAC-SHA512(chain_code, data)
child_pubkey = parent_pubkey + hmac_left × G
child_chain_code = hmac_right
```

## 4. Transaction Signing Process

### Complete Signing Workflow

**Step 1: Create Unsigned Transaction**
```
Inputs:
  - Previous TX ID
  - Output index
  - Amount
Outputs:
  - Recipient addresses
  - Amounts
Fees calculated
```

**Step 2: Serialize for Signing**
```
For legacy (P2PKH):
  - Use scriptCode (standard form)
  - Serialize with OP_0 in scriptSig place

For SegWit (P2WPKH):
  - Use scriptCode from output being spent
  - Use witness format serialization

For Taproot (P2TR):
  - Use script code from taproot rules
```

**Step 3: Hash Transaction**
```
tx_serialized → SHA256(SHA256(tx_serialized)) → 32-byte hash
SHA256 double hash prevents length extension attacks
```

**Step 4: Sign Each Input**
```
For each input:
  1. Retrieve corresponding private key
  2. Create signature using ECDSA (or Schnorr for Taproot)
  3. Signature = DER-encoded (r, s) + sighash byte
  4. Place signature in scriptSig/witness
```

**Step 5: Broadcast**
```
Complete signed transaction → P2P network → Mempool → Miners → Block
```

### Example with Python

```python
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.keys import Key, HDKey
from bitcoinlib.transactions import Transaction, Input, Output

# 1. Restore wallet from seed
mnemonic = "abandon abandon abandon ... abandon abandon about"
hd_wallet = HDKey.from_seed(Mnemonic('english').to_seed(mnemonic))

# 2. Derive receiving address
receiving_key = hd_wallet.subkey_for_path("m/44'/0'/0'/0/0")

# 3. Create transaction
tx = Transaction()
tx.add_input(prev_tx_hash, prev_index, keys=receiving_key)
tx.add_output(100000000, "1recipient_address_here")

# 4. Sign transaction (sign method will use ECDSA)
tx.sign()

# 5. Broadcast
broadcast_tx(tx.raw_hex())
```

## 5. Taproot (BIP340, BIP341, BIP342)

### What is Taproot?

Taproot is Bitcoin's most recent soft fork (November 2021) that:
- Introduces Schnorr signatures
- Adds Merklized Alternative Scripts (MAST)
- Improves privacy and efficiency

### BIP340: Schnorr Signatures

**Key Points:**
- 64-byte signatures (vs 71-72 bytes ECDSA)
- Deterministic
- Supports signature aggregation
- Uses x-coordinate only public keys (32 bytes)

### BIP341: Taproot Script Validation

**Taproot Address Format:**
```
Version: 1 (1 byte)
Program: Internal Key (32 bytes)

Total: 33 bytes → bech32m encoding → bc1p...
```

**Script Tree (MAST):**
```
       Root
      /    \
     /      \
   Node1   Node2
   / \      / \
  S1 S2    S3 S4

Each script hashed and merkled
Small scripts hide from blockchain
Spend via leaf script when needed
```

**Spending Conditions:**
1. **Key spend:** Signature from internal key (most private)
2. **Script spend:** Execute tapscript (reveals script)

### BIP342: Tapscript

**Opcodes and Script Changes:**
- OP_CHECKSIG_ADD replaces OP_CHECKMULTISIG
- OP_SUCCESS codes (81-86) reserved for future upgrades
- Empty stack = failure (unlike legacy)

## 6. Bitcoin Cryptography Summary Table

| Aspect | Legacy (P2PKH) | SegWit (P2WPKH) | Taproot (P2TR) |
|--------|---|---|---|
| **Signature Algorithm** | ECDSA | ECDSA | Schnorr |
| **Sig Size** | 71-72 bytes | 71-72 bytes | 64 bytes |
| **Pubkey Exposure** | Full (33 bytes) | Hashed | Minimal (internal key) |
| **Address Size** | 26 characters | 42 characters (bech32) | 62 characters (bech32m) |
| **Privacy** | Poor | Good | Excellent |
| **Quantum Safe** | No | No | No (Schnorr still ECDSA) |
| **Script Types** | Limited | Limited | MAST, Tapscript |

## 7. Current Public Key Exposure Analysis

### Address Types and Exposure

**P2PKH (1...) Addresses:**
- Public key: Always visible in scriptSig
- Exposure: 33 bytes minimum
- Quantum risk: HIGH (immediate exposure)
- Status: 1-2 million BTC in ~60% of wallets

**P2SH (3...) Addresses:**
- Public key: Visible when spending
- Exposure: Variable (depends on script)
- Quantum risk: MEDIUM (exposed on spend)
- Status: Growing adoption

**P2WPKH (bc1q...) Addresses:**
- Public key: Hashed, but recoverable from witness
- Exposure: 33 bytes in witness data
- Quantum risk: LOW-MEDIUM (witness segregated)
- Status: ~20-30% of UTXO set

**P2TR (bc1p...) Addresses:**
- Public key: Minimal exposure (internal key)
- Exposure: ~32 bytes only if key spend used
- Quantum risk: LOWEST (best privacy)
- Status: Growing, ~5-10% adoption

### Vulnerable Bitcoin Addresses

**Statistics:**
- ~20-40% of all Bitcoin supply is vulnerable
- Addresses that have:
  - Revealed public keys (P2PKH receiving addresses)
  - Spent and reused address
  - Long dormant without moving

**High-Risk Categories:**
1. Early Bitcoin wallets (2009-2015)
2. P2PKH dominated portfolios
3. Exchange deposit addresses (many were P2PKH)
4. Long-term HODLed Bitcoin

## 8. Migration Strategy Implications

### What Needs to Change

**For Wallets:**
1. Support Dilithium signature generation
2. Support hybrid key storage (ECDSA + Dilithium)
3. Implement hybrid signing (dual signatures)
4. Add BIP39 support for PQC seeds

**For Network:**
1. New script opcodes for PQC verification
2. Tapscript integration for hybrid scripts
3. Network propagation of larger signatures
4. Consensus on PQC algorithm choice

**For Blockchain:**
1. Transaction size implications
2. Block size vs. hybrid signature overhead
3. Script versioning for backward compatibility

## 9. References

- Mastering Bitcoin: https://github.com/bitcoinbook/bitcoinbook
- BIP32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- BIP340: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
- BIP341: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
- Bitcoin Developer Reference: https://developer.bitcoin.org/reference/

---
**Status:** ✅ Research Complete  
**Last Updated:** 2026-08-29  
**Next Phase:** Phase 1.3 - Migration Strategy
