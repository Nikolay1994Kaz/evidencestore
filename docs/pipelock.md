# Gateway journals (Pipelock)

[← README](../README.md)

A source with `"content_type": "pipelock/recorder"` carries the flight recorder of a [Pipelock](https://github.com/luckyPipewrench/pipelock) gateway: JSONL where every entry is hash-chained to the previous one and checkpoints are signed with the gateway's Ed25519 key. Pin that key in the source as `gateway_key` (64 hex, `pipelock signing pubkey`). Point the collector at the shards with a glob, since Pipelock writes every shard to a new file (full example: [`configs/collector.pipelock.example.json`](../configs/collector.pipelock.example.json)):

```json
{"glob": "/var/lib/pipelock/recorder/evidence-*.jsonl", "from_start": true}
```

At intake the store recomputes each entry's hash (Pipelock's frozen v1–v3 projections), checks the `prev_hash` linkage per writer and verifies checkpoint signatures with the pinned key. Nothing is rejected: the entry is stored as received, and a verdict goes into the chain next to it. The chain fields of the gateway (`seq`, `hash`, `prev_hash`) stay readable after the month key is destroyed.

A proof bundle for such a record also shows that the body is exactly that gateway entry (the hash is recomputed offline from the body) and that a checkpoint signed by the gateway covers it. Pass the gateway key to `esverify -gateway-key` to check that signature yourself. Limits: the linkage between the entry and the checkpoint was checked by the store at intake (the bundle does not carry the entries in between); a Pipelock restart starts a new chain, and the signed `chain-link` file that connects sessions is not checked yet; one writer per recorder directory. Verified against real Pipelock v3.6.0 output (`internal/gateway/testdata`) and end to end with a live Pipelock v3.6.0 (`scripts/demo-pipelock.sh`, and a night of a running gateway with restarts).
