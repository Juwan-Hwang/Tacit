# Tacit

A local-first, end-to-end encrypted sync engine for single-user multi-device scenarios.

Tacit enables zero-wait local writes, near-field sync over LAN, cross-internet near-real-time sync via QUIC, automatic offline catch-up, and relay fallback -- all without a central server.

## Features

- **Local-first**: Writes land locally before syncing asynchronously
- **CRDT-based**: Powered by [Loro](https://github.com/loro-dev/loro) for automatic conflict resolution and convergence
- **Multi-transport**: BLE Presence, LAN QUIC, WAN QUIC, and Relay fallback
- **End-to-end encrypted**: Device-key identity (Ed25519) + Noise Protocol Framework
- **Offline-tolerant**: Works fully offline, catches up automatically on reconnect
- **Shallow snapshots**: Efficient compaction via Loro shallow snapshots with dual-watermark GC

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   tacit-ffi                      │  UniFFI API, CommandBus, EventBus
├─────────────────────────────────────────────────┤
│                   tacit-sync                     │  SyncEngine, PeerRegistry, CheckpointManager
├──────────┬──────────┬───────────┬────────────────┤
│ tacit-   │ tacit-   │ tacit-    │ tacit-         │
│ transport│ transport│ transport │ transport      │  Transport abstractions
│          │ -quic    │ -ble      │ -relay         │
├──────────┴──────────┴───────────┴────────────────┤
│          tacit-crdt    │    tacit-crypto          │  CRDT + Encryption
│          tacit-store   │                          │  Storage
├─────────────────────────────────────────────────┤
│                   tacit-core                     │  Shared types, IDs, events, frames
└─────────────────────────────────────────────────┘
```

### Crates

| Crate | Description |
|---|---|
| `tacit-core` | Domain models, error types, config, protocol frames, Frontier, HLC, telemetry |
| `tacit-crdt` | Loro wrapper, Meta-Document, BlockDoc, BlockDocCache (LRU) |
| `tacit-store` | SQLite persistence: peers, acks, snapshots, checkpoints, WAL mode |
| `tacit-crypto` | Ed25519 device identity, signing, Noise_XX handshake, session keys, pairing |
| `tacit-transport` | Transport trait, frame codecs, batch signing, mDNS, store-and-forward |
| `tacit-transport-quic` | LAN/WAN QUIC via Quinn, fast-resume on network change |
| `tacit-transport-ble` | BLE presence broadcast/scan with mock and Linux BlueZ backends |
| `tacit-transport-relay` | Relay protocol: client/server, admission gate, session-level temp IDs |
| `tacit-sync` | SyncEngine, dependency wait queue, dual-watermark GC, stale peer recovery |
| `tacit-ffi` | UniFFI FFI layer, CommandBus, EventBus, RuntimeSupervisor, per-doc actors |
| `tacit-tests` | Integration, convergence (proptest), chaos, security, offline catch-up tests |

## Data Model

Tacit v1.0 supports four object types:

- **Text blocks** -- rich text content
- **Todo lists** -- checkable task items
- **Settings** -- key-value configuration
- **Logs** -- append-only entries

Each block is an independent Loro document. A **Meta-Document** manages block ordering, types, and soft-delete state.

## Quick Start

### Prerequisites

- Rust 1.85+ (see `rust-toolchain.toml`)
- No additional system dependencies for core crates

### Build

```bash
cargo build --workspace
```

### Test

```bash
# All tests
cargo test --workspace

# Integration tests only
cargo test --package tacit-tests

# Property-based convergence tests
cargo test --package tacit-tests convergence
```

### Usage (FFI layer)

```rust
use tacit_ffi::TacitEngine;

// Create engine (memory-backed for demo)
let engine = TacitEngine::new_memory("device-1")?;

// Create document and block
engine.create_document("doc1".into(), "note".into())?;
engine.create_block("doc1".into(), "block1".into(), "text".into())?;

// Edit
engine.apply_user_edit("doc1".into(), "block1".into(), b"Hello, Tacit!".to_vec())?;

// Open and read
let view = engine.open_document("doc1".into())?;
```

## Sync Protocol

### Frame Formats (Binary)

- **Discovery Frame**: `magic(2) | version(1) | group_id(4) | device_id(8) | capability_bits(2) | checksum(2)`
- **Control Frame**: `magic(2) | version(1) | ctrl_type(1) | session_id(8) | payload_len(2) | payload(n)`
- **Data Frame**: `magic(2) | version(1) | flags(1) | doc_id(8) | actor_id(8) | seq(4) | kind(1) | payload_len(4) | payload(n) | ref(8) | sig(batch)`

### Sync Flow

1. Discover peer (BLE / mDNS / known_peers)
2. Establish session with Noise handshake
3. Exchange AckSummary / frontier
4. Sync Meta-Document first
5. Pull blocks on demand
6. Dependency wait with exponential backoff for missing blocks
7. Update ack and evaluate compaction when complete

### Dual-Watermark GC

- **Hard frontier**: Intersection of all active device acks (safe compaction)
- **Soft frontier**: Union of all acks after removing stale devices (practical compaction)

## Security

- Device public key = identity (Ed25519)
- In-group pre-trust: all paired device keys are trusted
- Face-to-face pairing with short authentication code (SAS)
- Noise_XX handshake for session encryption
- Relay sees only connection metadata, never content

## Testing

| Test Suite | Coverage |
|---|---|
| Unit tests | Every module -- Frontier, HLC, frames, MetaDoc, BlockDoc, cache, sync engine |
| Property tests (proptest) | Delta out-of-order convergence, idempotent import, soft-delete safety, checkpoint+tail rebuild |
| Integration tests | 3-node LAN sync, Anchor offline switch, stale device catch-up, relay fallback, fast-resume, Noise handshake |
| Chaos tests | Random disconnects, packet loss simulation |
| Security tests | Peer spoofing, replay attacks, unauthorized relay access |

## License

MIT License -- Copyright (c) 2026 Juwan Hwang (黄治文)

See [LICENSE](LICENSE) for details.
