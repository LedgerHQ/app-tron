# Tron App — APDU Protocol

This document describes the APDU command set supported by the Ledger Tron application.

All commands share the class byte **`CLA = 0xE0`**.
Any other class byte is rejected with`0x6E00`.
The instruction byte (`INS`) selects the command.
Commands are dispatched in :
- [`src/handlers/dispatcher.c`](../src/handlers/dispatcher.c); the related constants are defined in
- [`src/handlers/handlers.h`](../src/handlers/handlers.h) and status words in
- [`src/app_errors.h`](../src/app_errors.h).

## Conventions

### APDU framing

| Field  | Size | Description                          |
| ------ | ---- | ------------------------------------ |
| `CLA`  | 1    | Always `0xE0`                        |
| `INS`  | 1    | Instruction (see table below)        |
| `P1`   | 1    | Parameter 1 (command-specific)       |
| `P2`   | 1    | Parameter 2 (command-specific)       |
| `Lc`   | 1    | Length of the command data           |
| `Data` | `Lc` | Command payload                      |

### BIP32 path encoding

Most commands begin their payload with a BIP32 derivation path:

```
[1 byte]  number of path elements (1..10)
[4 bytes] element 0   (big-endian, hardening bit included)
...
[4 bytes] element n-1 (big-endian)
```

Maximum depth is 10 elements (`MAX_BIP32_PATH`). The standard Tron path is `m/44'/195'/0'/0/0`.

### Signature format

All signing commands return a 65-byte signature:

```
[32 bytes] r
[32 bytes] s
[1 byte]   v  (recovery parity: 0x00 or 0x01)
```

The curve is **secp256k1**.

## Supported instructions

| INS    | Name                        | Handler                       | Purpose                                  |
| ------ | --------------------------- | ----------------------------- | ---------------------------------------- |
| `0x02` | `INS_GET_PUBLIC_KEY`        | `handleGetPublicKey`          | Derive public key & Tron address         |
| `0x04` | `INS_SIGN`                  | `handleSign`                  | Sign a protobuf-encoded transaction      |
| `0x05` | `INS_SIGN_TXN_HASH`         | `handleSignByHash`            | Sign a raw 32-byte transaction hash      |
| `0x06` | `INS_GET_APP_CONFIGURATION` | `handleGetAppConfiguration`   | Return settings flags & app version      |
| `0x08` | `INS_SIGN_PERSONAL_MESSAGE` | `handleSignPersonalMessage`   | Sign a TRON personal message             |
| `0x0A` | `INS_GET_ECDH_SECRET`       | `handleECDHSecret`            | Compute an ECDH shared secret            |
| `0x0C` | `INS_SIGN_TIP_712_MESSAGE`  | `handleSignTIP712Message`     | Sign a TIP-712 (EIP-712) typed message   |

When the app is invoked **from Exchange/Swap**, only `INS_GET_PUBLIC_KEY` and `INS_SIGN` are
accepted; any other instruction returns `0x6A8E`.

---

### `0x02` — GET PUBLIC KEY

Derives the secp256k1 public key and Base58Check Tron address for a BIP32 path.

**P1**

| Value  | Name             | Meaning                                |
| ------ | ---------------- | -------------------------------------- |
| `0x00` | `P1_NON_CONFIRM` | Return immediately, no user approval   |
| `0x01` | `P1_CONFIRM`     | Display the address for user approval  |

**P2** (only the low 6 bits are considered)

| Value  | Name              | Meaning                          |
| ------ | ----------------- | -------------------------------- |
| `0x00` | `P2_NO_CHAINCODE` | Do not return the chain code     |
| `0x01` | `P2_CHAINCODE`    | Append the 32-byte chain code    |

**Command data**

```
[BIP32 path]
```

**Response**

```
[1 byte]   public key length (= 65)
[65 bytes] uncompressed secp256k1 public key
[1 byte]   address length (= 34)
[34 bytes] Base58Check Tron address (ASCII)
[32 bytes] chain code            (only when P2 = 0x01)
```

> In Swap mode, `P1_CONFIRM` is rejected with `0x6A8E`.

---

### `0x04` — SIGN (transaction)

Streams a protobuf-encoded Tron transaction in one or more chunks, parses it, displays the
relevant details for approval, and returns the signature. The transaction is hashed with SHA-256
as it is streamed.

**P1**

| Value         | Name            | Meaning                                                       |
| ------------- | --------------- | ------------------------------------------------------------- |
| `0x10`        | `P1_SIGN`       | Single-chunk transaction (path + full transaction)            |
| `0x00`        | `P1_FIRST`      | First chunk (path + start of transaction)                     |
| `0x80`        | `P1_MORE`       | Intermediate chunk (transaction data only)                    |
| `0x90`        | `P1_LAST`       | Final chunk (transaction data only)                           |
| `0xA0`–`0xAF` | `P1_TRC10_NAME` | Token-name / exchange-pair metadata chunk (see below)         |

For `P1_TRC10_NAME` the low nibble encodes the slot and a "last" flag:
- bits `0..2` — token index (max 2 token names; max 1 exchange pair)
- bit `3` (`0x08`) — set on the last metadata chunk

**P2** — must be `0x00`.

**Command data**

- `P1_FIRST` / `P1_SIGN`: `[BIP32 path][protobuf transaction bytes]`
- `P1_MORE` / `P1_LAST`: `[protobuf transaction bytes]`
- `P1_TRC10_NAME`: token name(s) for TRC10 transfers / exchange-create, or the trading pair for
  exchange inject/withdraw/transaction contracts.

**Response**

- Non-final chunk accepted: status `0x9000`, no data.
- Final chunk, after user approval: `[65-byte signature]`.

**Supported contract types** (each rendered on a dedicated approval screen): TRX transfer
(`TransferContract`), TRC10 transfer (`TransferAssetContract`), TRC20 / smart-contract trigger
(`TriggerSmartContract` — transfer, approve, or custom call), exchange create/inject/withdraw/
transaction, vote witness, freeze/unfreeze (v1 and v2), delegate/undelegate resource, withdraw
expired unfreeze, withdraw balance (claim rewards), and account permission update.

**Relevant settings & errors**

- Custom (non transfer/approve) smart-contract calls require the *Custom contracts* setting,
  else `0x6A8D`.
- Contracts with extra `data` require the *Data allowed* setting, else `0x6A8B`.
- `AccountPermissionUpdate` and any contract type not individually rendered require the
  *Sign by hash* setting, else `0x6A8C`.
- In Swap mode only `TransferContract` and TRC20 transfers are allowed; otherwise `0x6A8E`.

---

### `0x05` — SIGN TRANSACTION HASH

Signs an externally-computed 32-byte transaction hash. This is an "unsafe" / blind-signing path:
it requires the **Sign by hash** setting to be enabled.

**P1** — must be `0x00`. **P2** — must be `0x00`.

**Command data**

```
[BIP32 path]
[32 bytes] transaction hash
```

**Response**

```
[65-byte signature]   (after user approval)
```

If the *Sign by hash* setting is disabled, returns `0x6A8C`.

---

### `0x06` — GET APP CONFIGURATION

Returns the active settings flags and the application version. Takes no input; `P1`/`P2`/data are
ignored.

**Response** (4 bytes)

```
[1 byte] settings flags (low nibble, see below)
[1 byte] major version
[1 byte] minor version
[1 byte] patch version
```

**Settings flag bits** (defined in [`src/settings.h`](../src/settings.h))

| Bit | Constant             | Meaning                                |
| --- | -------------------- | -------------------------------------- |
| 0   | `S_DATA_ALLOWED`     | Allow contracts carrying `data`        |
| 1   | `S_CUSTOM_CONTRACT`  | Allow arbitrary smart-contract calls   |
| 2   | `S_TRUNCATE_ADDRESS` | Display truncated addresses            |
| 3   | `S_SIGN_BY_HASH`     | Allow blind signing by hash            |

---

### `0x08` — SIGN PERSONAL MESSAGE

Signs an arbitrary message using the TRON personal-message scheme. The message is prefixed with
`\x19TRON Signed Message:\n<length>` and hashed with **Keccak-256**. The message may be streamed
across multiple chunks.

**P1**

| Value  | Name        | Meaning                                                |
| ------ | ----------- | ------------------------------------------------------ |
| `0x10` | `P1_SIGN`   | Single-chunk message (path + length + data)            |
| `0x00` | `P1_FIRST`  | First chunk (path + length + start of message)         |
| `0x80` | `P1_MORE`   | Continuation chunk (message data only)                 |

**P2** — must be `0x00`.

**Command data**

- `P1_FIRST` / `P1_SIGN`:
  ```
  [BIP32 path]
  [4 bytes] total message length (big-endian)
  [N bytes] message data
  ```
- `P1_MORE`: `[message data]`

The cumulative data must not exceed the announced length (`0x6700` otherwise).

**Response**

- Intermediate chunk: status `0x9000`, no data.
- After the full message is received and approved: `[65-byte signature]`.

---

### `0x0A` — GET ECDH SECRET

Computes an ECDH shared secret between the device key (derived from a BIP32 path) and a supplied
peer public key. The operation is shown for user approval.

**P1** — must be `0x00`. **P2** — must be `0x01`.

**Command data**

```
[BIP32 path]
[65 bytes] peer uncompressed secp256k1 public key
```

**Response**

```
[65 bytes] ECDH shared point (0x04 || X || Y)   (after user approval)
```

---

### `0x0C` — SIGN TIP-712 MESSAGE

Signs TIP-712 (EIP-712 equivalent) typed structured data from a pre-computed domain hash and
message hash. The device computes `keccak256(0x1901 || domainHash || messageHash)` and signs it.
Requires the **Sign by hash** setting.

**P1** — must be `0x00`. **P2** — must be `0x00`.

**Command data**

```
[BIP32 path]
[32 bytes] domain separator hash
[32 bytes] message hash
```

**Response**

```
[65-byte signature]   (after user approval)
```

If the *Sign by hash* setting is disabled, returns `0x6A8C`.

---

## App specific status words

Defined in [`src/app_errors.h`](../src/app_errors.h).

| SW       | Constant                            | Meaning                                              |
| -------- | ----------------------------------- | ---------------------------------------------------- |
| `0x9000` | `E_OK`                              | Success                                              |
| `0x6700` | `E_INCORRECT_LENGTH`                | Wrong data length                                    |
| `0x6800` | `E_MISSING_CRITICAL_PARAMETER`      | Missing critical parameter                           |
| `0x6982` | `E_SECURITY_STATUS_NOT_SATISFIED`   | Security status not satisfied (e.g. key derivation)  |
| `0x6985` | `E_CONDITIONS_OF_USE_NOT_SATISFIED` | User rejected the operation                          |
| `0x6A80` | `E_INCORRECT_DATA`                  | Malformed/invalid command data                       |
| `0x6B00` | `E_INCORRECT_P1_P2`                 | Invalid `P1`/`P2`                                    |
| `0x6A8A` | `E_INCORRECT_BIP32_PATH`            | Invalid BIP32 path                                   |
| `0x6A8B` | `E_MISSING_SETTING_DATA_ALLOWED`    | "Data allowed" setting required                      |
| `0x6A8C` | `E_MISSING_SETTING_SIGN_BY_HASH`    | "Sign by hash" setting required                      |
| `0x6A8D` | `E_MISSING_SETTING_CUSTOM_CONTRACT` | "Custom contracts" setting required                  |
| `0x6A8E` | `E_SWAP_CHECKING_FAIL`              | Operation not allowed / failed validation in Swap    |
| `0x6D00` | `E_INS_NOT_SUPPORTED`               | Unknown instruction                                  |
| `0x6E00` | `E_CLA_NOT_SUPPORTED`               | Wrong class byte (`CLA != 0xE0`)                     |
| `0x6F00` | `E_TECHNICAL_PROBLEM`               | Internal error                                       |

