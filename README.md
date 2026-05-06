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
| `libp2p-cat-noise`     | Noise XX handshake + AEAD transport over datagrams; messages 2 and 3 carry an arbitrary encrypted trailer. |
| `libp2p-cat-identity`  | Ed25519 ↔ X25519 binding: `SignedStaticKey` payload (96 bytes) carried as the XX handshake trailer. |
| `libp2p-cat-host`      | Connection-managing host: dial / send / recv loop; verifies every peer's identity binding and surfaces the resolved `PeerId` on `HandshakeComplete`. |
| `libp2p-cat-pubsub`    | `PubsubMux` over `Host`: kind-byte multiplexed app data + RLNC pubsub with source / decoder / relay roles. |
| `libp2p-cat-kad`       | Kademlia DHT: `NodeId`, XOR `Distance`, k-buckets, `RoutingTable`, a `KademliaNode` driver over `Host` that auto-answers `PING` / `FIND_NODE`, and a synchronous iterative `lookup_node` that transparently dials newly-discovered peers and converges to up to `k` peers closest to a target. |
| `libp2p-cat-rendezvous`| NAT-traversal primitives: `RendezvousNode` over `Host` exposing STUN-style `OBSERVE` plus `PUNCH` coordination (server forwards a relay to the target, target auto-fires a bare-datagram punch back at the initiator). |
| `libp2p-cat-mux`       | `MultiProtocolNode<A>`: holds one `Host` + `PubsubState<A>` + `RoutingTable`, dispatching a 1-byte kind-byte plaintext envelope (`KIND_APP` / `KIND_PUBSUB` / `KIND_KAD` / `KIND_RENDEZVOUS`) so all four flows share one UDP socket. |
| `libp2p-cat-rs`        | Top-level umbrella re-exporting all of the above.        |

A runnable two-peer chat example lives at `examples/chat/`:

```bash
# terminal 1 (responder)
cargo run -p libp2p-cat-rs-example-chat -- 127.0.0.1:4001
# terminal 2 (initiator)
cargo run -p libp2p-cat-rs-example-chat -- 127.0.0.1:4002 127.0.0.1:4001
```

A two-binary STUN-style address-observation demo lives at
`examples/rendezvous-demo/`:

```bash
# terminal 1 (long-running rendezvous server)
cargo run --bin rendezvous-server -- 127.0.0.1:5555

# terminal 2 (one-shot client; prints the address the server saw)
cargo run --bin rendezvous-observe -- 127.0.0.1:0 127.0.0.1:5555
```

`PubsubMux` is generic over an authenticator that implements
`WireAuthenticator`.  Three stock impls ship in `libp2p-cat-pubsub`:

| Authenticator                       | Wire overhead per piece          | Relay model                |
| ----------------------------------- | -------------------------------- | -------------------------- |
| `NullAuthenticator`                 | 0 + 0 bytes                      | trust-the-peer             |
| `KeyedHashAuthenticator`            | 32 + 32 bytes (BLAKE3-keyed)     | permissioned (shared key)  |
| `LatticeHomomorphicAuthenticator`   | 32 + 4 + 8·m bytes (`Z^m` sig)   | open (homomorphic re-tag)  |

Future:

| Piece                  | Purpose                                                  |
| ---------------------- | -------------------------------------------------------- |
| Rendezvous (later)     | TURN-style relay fallback for symmetric NATs.            |

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
