# Evidence for purchases made by AI agents

[← README](../README.md)

An agent that buys for a customer leaves a question for any later dispute: what did the customer allow, what did the agent do, and do the two match. Whoever answers it, the agent platform or the merchant, is a party to that dispute, and a log it could have edited convinces no one. If every step of a purchase goes into a store under another administrator as it happens, the platform can later hand over one purchase as a bundle that the other side verifies offline: the exact lines, when the store received them, and that none of the lines of that source was left out.

Nothing in the store is specific to purchases. This page is a convention for the log lines, the setting that makes one purchase a subject of the source, and a script that prints a verified bundle as the story of that purchase. `scripts/demo-purchase.sh` plays it end to end.

## What the agent writes

One JSON object per line, written when the step happens. Every line carries `purchase_id` at the top level; `event` names the step. The store does not check the other fields, and `scripts/purchase-report.py` reads the ones below.

| `event` | Written when | Fields |
|---|---|---|
| `mandate` | the customer's instruction reaches the agent | `customer`, `instruction`, `scope` (`price_cap`, `currency`, `merchants`, `expires`), `credential`: the signed mandate exactly as received |
| `agent_verified` | the merchant has checked who the agent is | `agent_id`, `key_id`, `checked_by`, `result` |
| `cart` | the agent has fixed what it buys | `merchant`, `items` (`sku`, `name`, `qty`, `price`), `total`, `currency` |
| `notification` | the customer is told and can still cancel | `channel`, `cancel_until` |
| `cancel` | the customer or the agent calls the purchase off | `by`, `channel` |
| `payment` | the payment is made | `amount`, `currency`, `method`, `token_ref`, `authentication`, `network_ref` |
| `delivery` | the goods or the service arrive | `carrier`, `tracking`, `status` |

`at` in a line is the agent's own clock and proves nothing; what a bundle proves is when the store received the line.

- **`purchase_id`** is a string or a number of at most 256 bytes, spelled the same way in every line of the purchase: values are compared as written, so `P-1002` and `p-1002` are two purchases. A line without it, with it twice or below the top level gets no label and never opens in a purchase bundle (`evidencestore_records_without_subject_total` counts such lines).
- **Signed objects go in as received.** The mandate credential (an AP2 mandate, for example), the agent's signed request, the merchant's signed cart: put what you got into the line as it came (base64 if it is not text). The store gives a record back byte for byte, so anyone can check those signatures later with the signer's key. The store itself does not check them in this release; the only signatures it checks at intake are those of a Pipelock journal ([Gateway journals](pipelock.md)). `purchase-report.py` checks one form of the mandate: a compact JWS (RFC 7515) signed with ES256 whose claims repeat the line's `purchase_id`, `customer`, `instruction` and `scope`.
- **Write the line when the step happens.** A line written after the dispute began is received after it began, and the time-stamps show that.
- **A line is a record of at most about 1 MiB**; a longer one is cut into several. Keep a page snapshot or a receipt image elsewhere and write its SHA-256 into the line.
- **No card numbers.** Write the token reference and the network's reference of the payment.

## Settings

The source names the field ([Configuration](configuration.md)); the collector follows the file the agent appends to. Examples: [`configs/evidencestore.purchases.example.json`](../configs/evidencestore.purchases.example.json), [`configs/collector.purchases.example.json`](../configs/collector.purchases.example.json).

```json
{"name": "shop-agent", "content_type": "purchase-events", "subject_field": "purchase_id", "retention_months": 24}
```

A source has one `subject_field`, and a record keeps the field it was labelled by, so pick it once: with `purchase_id` a bundle opens one purchase, not everything about one customer. Set `retention_months` to at least the time in which a purchase can still be disputed under the rules of your payment methods: once a month's key is destroyed, its bodies are gone in every copy.

## One purchase as a bundle

```sh
evidencestore proof -config store.json -source shop-agent -subject p-1002 -from FROM -to TO -out p-1002.json
esverify -proof p-1002.json -store-key store.pub -tsa-trust tsa-root.crt -bodies p-1002/
python3 scripts/purchase-report.py -proof p-1002.json -store-key store.pub -tsa-trust tsa-root.crt -purchase p-1002 -mandate-key customer.pub
```

`FROM` and `TO` (RFC 3339, the store's receive time) must cover the purchase from its mandate to its last line. The window is closed by a time-stamp taken more than two minutes after `TO`, and the bundle is ready one time-stamp later ([Bundles, One subject](bundles.md)). `purchase-report.py` runs `esverify` itself and prints the purchase only when the bundle verifies: the mandate, who the agent was, the cart against the mandate, the notice and the time left to cancel, the payment, the delivery, and where they disagree.

With `-mandate-key`, the public key (PEM) of whoever signed the mandate, the script checks the mandate's signature through `openssl`, and then compares the cart with what was signed, not with what the line next to it says: the price cap, the merchants, the expiry. It also says when the line differs from what was signed, and when the signed mandate names another purchase. Without the key, or for a credential in another form, the report says that the signature was not checked, and the mandate is the line's word.

## What a purchase bundle proves, and what it does not

Proven, by `esverify` and without trusting the store or the platform:

- every line of the window under the purchase's label, byte for byte, and that the store received each one between two TSA time-stamps;
- that no line of the source in the window is left out of the bundle. A cancellation, a second cart or a failed check cannot be dropped from the answer: a bundle with one of the purchase's lines removed does not verify;
- nothing about other purchases is opened: their lines travel encrypted and without keys.

Not proven:

- **That a line is true, or that every step was written.** The agent platform writes the lines. A step it never wrote is not in the store, and nothing in a bundle shows that it is missing.
- **That every line of the purchase is under its label.** The store sets the label when it receives a line, from the `purchase_id` in it; a line that names another purchase, or none, is not in this bundle ([Bundles](bundles.md) says what a store dishonest at intake could do).
- **Any signature inside a line, by the store or by `esverify`.** `purchase-report.py -mandate-key` checks the mandate's when it is a compact JWS with ES256, and whose key that is, is for you to establish: a key the platform hands you proves nothing against the platform. An SD-JWT with disclosures and key binding, which is how AP2 carries mandates, is not parsed, and neither is the agent's signature: check those yourself, from the bodies `esverify -bodies` writes.
- **Who pays.** A bundle is evidence of what was recorded and when. Whether it settles a dispute is decided by the rules of the payment method and by whoever applies them.

Limits to plan for:

- **The bundle grows with the whole source, not with the purchase.** It carries every record the source wrote in the window, the other purchases' as encrypted evidence, and one bundle spans at most 250 000 leaves of the chain. Ask for a narrow window, and for a purchase that runs for days, window by window.
- **The other purchases stay closed, not invisible.** Of each of their lines the bundle shows the number, the receive time, the length and a label, so the lines of one unnamed purchase can be told from another's within a month.
- **Erasure is by source and month.** One customer's lines cannot be destroyed apart from the rest of the month ([Keys and retention](keys.md)).
- **One source, one bundle.** A purchase recorded by two sources, the agent platform and the merchant, takes a bundle from each; labels of different sources do not match.

## Try it

```sh
scripts/demo-purchase.sh                       # builds everything, runs offline, takes about three minutes; needs openssl
ES_BIN=/usr/local/bin scripts/demo-purchase.sh # the same on installed binaries
```

An agent makes three purchases through one log, each under a mandate signed with its customer's key. The script asks the store for the bundle of the second one, verifies it, shows that the lines of the other two purchases stay closed, and prints the report with the mandate checked under the customer's public key; under another customer's key the signature does not verify. Then it changes one byte of the cart and, in another copy, takes the notification out of the bundle: neither copy verifies.
