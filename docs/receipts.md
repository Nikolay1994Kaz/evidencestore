# Gateway receipts

[← README](../README.md)

A gateway is what an AI agent acts through: an MCP server, a purchase platform, a proxy in front of an API. When it writes one signed line for every step of every action, the store checks at intake that each line is the gateway's and that none is missing from its chain, and a bundle over one action shows the same to anyone who holds the gateway's public key. The content type is `receipt/v1`. Pipelock's flight recorder keeps its own format and is checked by its own rules ([Gateway journals](pipelock.md)).

## The line

One JSON object per line:

| Field | Value | Meaning |
|---|---|---|
| `v` | `1` | the format version |
| `gateway` | 1 to 128 of `A–Z a–z 0–9 . _ : -` | the gateway instance that writes the chain; it stays readable in the store's verdicts, so put no personal data in it |
| `seq` | an integer from 1 to 2^53 − 1 | one more than the gateway's previous receipt |
| `prev` | `"genesis"` or 64 lowercase hex | SHA-256 of the gateway's previous line, as written, without the newline |
| `time` | RFC 3339 | the gateway's clock; it proves nothing, the store's receive time does |
| `action` | a string of 1 to 256 bytes | the action the step belongs to: a purchase, a change to a database; the store labels the line by it |
| `step` | 1 to 64 of `A–Z a–z 0–9 . _ : -` | what happened: `mandate`, `cart`, `intent`, `outcome`… |
| `refs` | optional: up to 64 objects `{"source": S, "subject": V}` | where the same action is recorded in another source of the store: under subject V of source S, such as a database's transaction id or a payment network's reference |
| `approval` | optional: `{"format": F, "credential": C}` | who allowed the action, exactly as received: a customer's mandate, an operator's confirmation; the store does not parse it |
| `body` | optional: any JSON | what the gateway knows about the step |
| `sig` | 128 lowercase hex, the last field | the Ed25519 signature |

```json
{"v":1,"gateway":"shop-agent-1","seq":7,"prev":"5f0c…e1","time":"2026-11-23T12:00:03.1Z","action":"p-1002","step":"cart","body":{"merchant":"sport.example","total":54990,"currency":"KZT"},"sig":"9a41…0c"}
```

**The signature** covers the line without `sig`. Write the object without it (bytes B, ending in `}`), sign `evidencestore/receipt/v1` and a newline followed by B with the gateway's Ed25519 key, and write B without its last `}`, then `,"sig":"<128 lowercase hex>"}`, then a newline. A verifier cuts this tail off, puts the `}` back and checks the very bytes that were signed, so no canonical form of JSON is needed: the gateway may order keys and escape strings as its JSON library does. At the top level, in `refs` and in `approval` a key may not appear twice, also in another case (`step` and `STEP` are one key: some parsers take one, some the other), and no other field is allowed there; `body` is free. The line is valid UTF-8, with no half of a surrogate pair escaped alone, and fits in one store record (1 MiB minus 1 KiB): a longer one is cut into pieces by the collector, and no piece is a receipt. Keep a large payload elsewhere and put its SHA-256 into `body`.

**The chain.** A gateway's first receipt has `"seq": 1, "prev": "genesis"`, every next one the next `seq` and the hash of the line before it. A gateway that restarts goes on from its last line; one that starts over from `genesis` shows in the store as a break, since receipts may have been lost in between. Several gateway instances can write into one source, each its own chain under its own `gateway`.

**Write the receipt before the step takes effect** when the step is a promise: an intent goes to disk (fsync) before the database's `COMMIT`, the outcome in a receipt after it. A receipt written after a dispute began is received after it began, and the time-stamps show that.

## Writing receipts: esreceipt

For a gateway not written in Go, and for scripts:

```sh
esreceipt keygen -key gateway.key        # PKCS#8 PEM, mode 0600; prints the public key for gateway_key
echo '{"action":"p-1002","step":"cart","body":{"total":54990}}' |
  esreceipt sign -key gateway.key -gateway shop-agent-1 -file /var/log/shop-agent/receipts.jsonl
esreceipt verify -gateway-key <64 hex> -file /var/log/shop-agent/receipts.jsonl
```

`sign` takes one step per input line (`action` and `step`, and if needed `time`, `refs`, `approval`, `body`), goes on from the gateway's last receipt in the file, holds a lock on the file while it writes, and fsyncs every receipt before the next. A line in the file that is not a receipt of this gateway signed with this key, such as a forgery added by someone who can write the file but has no key, does not stop it: it warns, and the chain goes on past that line, so the store flags only the forgery. If lines claim the gateway and none of them is signed with the key given, `sign` refuses, since the key is most likely the wrong one. A file that does not end with a newline has a torn last line: `sign` refuses until it is removed. `verify` checks a file by the same rules as the store and names every line that is not intact. A gateway written in Go uses the `gateway.Signer` of this repository the same way (an internal package for now).

Keep the key readable only by the gateway's own system user. Whoever can read it signs receipts in the gateway's name: an agent given a shell on the gateway's host under the same user, too.

## Settings

```json
{"name": "shop-agent", "content_type": "receipt/v1", "gateway_key": "<64 hex>", "subject_field": "action", "retention_months": 24}
```

`gateway_key` is required for this content type: a receipt whose signature nobody checked proves nothing. `subject_field` is `action` or none; with it, `evidencestore proof -subject` opens the receipts of one action and no others ([One subject](bundles.md)). Point the collector at the file the gateway writes.

## What the store checks at intake

Every line: the format above, the signature with the pinned key, and the link to the receipt of the same gateway the store received before it. Nothing is rejected. The line is stored as received, and a verdict goes into the chain next to it: the gateway, `seq`, the hash of the line and its `prev`, the link (`genesis`, `linked`, `first-seen` when the chain began before the store's first receipt of it, `broken`), the signature (`valid` or `invalid`) and what is wrong. The action, the step and the body are not in the verdict, so a bundle for one action keeps the others closed. A line whose signature is not the gateway's does not enter the gateway's chain: the next real receipt links past it. Every line that is not intact counts in `evidencestore_gateway_problems_total` and goes to the store's log.

## What a bundle proves

A single-record bundle (`evidencestore proof -source S -seq N`) shows that its body is the very line the verdict describes (the hash is recomputed) and that it parses offline; with `esverify -gateway-key`, that the gateway signed it. A bundle for one action (`evidencestore proof -source S -subject ACTION -from FROM -to TO`) opens that action's receipts and keeps the others closed. With `esverify -gateway-key` it checks the signature of every open receipt, and it checks the chain across the whole window from the verdicts: two neighbouring receipts of a gateway link by hash exactly as their verdicts say. So a closed receipt between two open ones is named by the signed `prev` of the next: it was neither left out nor swapped, whatever it says. Receipts the store found broken at intake are not opened, and the report names them.

Not proven:

- **That a receipt is true.** The signature shows who wrote it, the holder of the gateway key, and that it is unchanged since; a false step the gateway signed is recorded faithfully.
- **That every step was written.** A step the gateway never wrote is not in the store, and nothing in a bundle shows that it is missing.
- **Whose key it is.** Establish that yourself: a key the gateway's operator hands you proves nothing against that operator.
- **Which receipts are the action's.** That rests on the label the store set at intake from `action`, as for any subject ([Bundles](bundles.md)).
- **The other sources a receipt names.** `refs` are the gateway's word. This release does not build one bundle across sources: ask each named source for its own bundle of that subject.

Limits to plan for:

- **One key per source.** A new key takes a config change; verdicts already in the chain keep what they said. Check older receipts with the older key.
- **The bundle grows with the whole source**, not with the action, as every bundle over a window does ([Purchases](purchases.md)).
- **A receipt is one record.** Anything bigger goes elsewhere, with its hash in `body`.
