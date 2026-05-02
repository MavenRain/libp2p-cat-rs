# libp2p-cat-rs

A categorical, UDP-only, RLNC-native peer-to-peer stack built on
[`comp-cat-rs`](https://crates.io/crates/comp-cat-rs) and
[`rlnc-cat-rs`](https://crates.io/crates/rlnc-cat-rs).

This is a deliberately reduced re-imagining of [libp2p](https://libp2p.io):

- **UDP only.** No TCP, no QUIC, no WebSocket. Every transport address in
  the type system is a `UdpAddr`.
- **Datagram-native reliability.** Application protocols own their
  loss-handling. RLNC tolerates loss intrinsically; control-plane RPC
  uses explicit retries (via [`tarpc-cat`](https://crates.io/crates/tarpc-cat)
  in a later crate).
- **No async runtime.** All effects are `Io<Error, _>` from `comp-cat-rs`;
  blocking I/O is suspended with `Io::suspend` and run at the boundary.
- **RLNC pubsub by default.** Multicast goes through `rlnc-cat-rs::gossip`;
  every relay recodes pieces.
- **libp2p-compatible PeerIDs.** Public keys are protobuf-encoded and
  multihashed exactly as libp2p does, so PeerIDs are recognisable.

## Workspace layout

| Crate                  | Purpose                                                  |
| ---------------------- | -------------------------------------------------------- |
| `libp2p-cat-types`     | `PeerId`, `UdpAddr`, `ProtocolId`, workspace `Error`.    |
| `libp2p-cat-udp`       | `UdpTransport`: linear `Io`-shaped UDP datagram socket.  |
| `libp2p-cat-noise`     | Noise XX handshake + AEAD transport over datagrams.      |
| `libp2p-cat-pubsub`    | RLNC pubsub on top of `rlnc-cat-rs::gossip`.             |
| `libp2p-cat-host`      | Connection-managing host: dial / send / recv loop.       |
| `libp2p-cat-rs`        | Top-level umbrella re-exporting the four layers above.   |

A runnable two-peer chat example lives at `examples/chat/`:

```bash
# terminal 1 (responder)
cargo run -p libp2p-cat-rs-example-chat -- 127.0.0.1:4001
# terminal 2 (initiator)
cargo run -p libp2p-cat-rs-example-chat -- 127.0.0.1:4002 127.0.0.1:4001
```

Future:

| Piece                  | Purpose                                                  |
| ---------------------- | -------------------------------------------------------- |
| `libp2p-cat-identity`  | Ed25519 ↔ X25519 binding via signed-Noise-extension.     |
| pubsub-on-host         | Layer pubsub on top of host so one socket carries both.  |
| RLNC relay/recode      | Multi-hop pubsub: each relay verifies+recodes pieces.    |
| Kademlia DHT           | Peer discovery and content routing.                      |
| NAT traversal          | Rendezvous-based UDP hole-punching.                      |

## Why UDP-only?

Constraining the wire to UDP buys us:

- A single, MTU-bounded packet abstraction that composes cleanly with
  RLNC pieces (each piece fits in one datagram).
- Cheap NAT hole-punching (deferred to v2) without the multi-RTT QUIC
  handshake.
- A clean `Io`-shaped transport with no implicit byte-stream semantics.

It costs us:

- No backpressure framing for free; reliability is per-protocol.
- No TCP-compat with existing libp2p deployments. We are a
  non-interoperable fork on the wire, but PeerID-compatible at the
  identity layer.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE)
at your option.
