# Evidence for purchases made by AI agents

[← README](../README.md)

An agent that buys for a customer leaves a question for any later dispute: what did the customer allow, what did the agent do, and do the two match. Whoever answers it, the agent platform or the merchant, is a party to that dispute, and a log it could have edited convinces no one. If every step of a purchase goes into a store under another administrator as it happens, signed by the platform, the platform can later hand over one purchase as a bundle that the other side verifies offline: the exact steps, that the platform signed each of them, when the store received them, and that none of the steps of that source was left out.

Nothing in the store is specific to purchases. Every step is a [gateway receipt](receipts.md) of the platform; this page is a convention for what those receipts say, the setting that makes one purchase a subject of the source, and a script that prints a verified bundle as the story of that purchase. `scripts/demo-purchase.sh` plays it end to end.

## What the platform writes

A gateway receipt for every step, signed with the platform's gateway key (`esreceipt sign`, see [Gateway receipts](receipts.md)). `action` is the purchase, `step` names the step, and `body` carries the fields below. The store does not check them, and `scripts/purchase-report.py` reads these:

| `step` | Written when | `body` |
|---|---|---|
| `mandate` | the customer's instruction reaches the agent | `customer`, `instruction`, `scope` (`price_cap`, `currency`, `merchants`, `expires`); the signed mandate goes into `approval` |
| `agent_verified` | the merchant has checked who the agent is | `agent_id`, `key_id`, `checked_by`, `result` |
| `cart` | the agent has fixed what it buys | `merchant`, `items` (`sku`, `name`, `qty`, `price`), `total`, `currency` |
| `notification` | the customer is told and can still cancel | `channel`, `cancel_until` |
| `cancel` | the customer or the agent calls the purchase off | `by`, `channel` |
| `payment` | the payment is made | `amount`, `currency`, `method`, `token_ref`, `authentication`, `network_ref`; `refs` names the payment as the network's source would label it |
| `delivery` | the goods or the service arrive | `carrier`, `tracking`, `status` |

`time` in a receipt is the platform's clock and proves nothing; what a bundle proves is when the store received the receipt.

- **`action`** is the purchase id, a string of at most 256 bytes, spelled the same way in every receipt of the purchase: values are compared as written, so `P-1002` and `p-1002` are two purchases.
- **Signed objects go in as received.** The mandate credential (an AP2 mandate, for example) goes into `approval` with its format, `{"format": "jws", "credential": "…"}`; the agent's signed request and the merchant's signed cart go into `body` as they came (base64 if they are not text). The store gives a record back byte for byte, so anyone can check those signatures later with the signer's key. The store checks the platform's signature on every receipt; the signatures inside a receipt it does not check. `purchase-report.py` checks one form of the mandate: a compact JWS (RFC 7515) signed with ES256 whose claims repeat the receipt's purchase (`purchase_id`), `customer`, `instruction` and `scope`.
- **Write the receipt when the step happens.** A receipt written after the dispute began is received after it began, and the time-stamps show that.
- **A receipt is a record of at most 1 MiB minus 1 KiB.** Keep a page snapshot or a receipt image elsewhere and write its SHA-256 into `body`.
- **No card numbers.** Write the token reference and the network's reference of the payment.

## Settings

The source names the platform's gateway key and labels by `action` ([Configuration](configuration.md)); the collector follows the file the platform writes its receipts to. Examples: [`configs/evidencestore.purchases.example.json`](../configs/evidencestore.purchases.example.json), [`configs/collector.purchases.example.json`](../configs/collector.purchases.example.json).

```json
{"name": "shop-agent", "content_type": "receipt/v1", "gateway_key": "<64 hex, printed by esreceipt keygen>", "subject_field": "action", "retention_months": 24}
```

With `action` as the subject, a bundle opens one purchase, not everything about one customer. Set `retention_months` to at least the time in which a purchase can still be disputed under the rules of your payment methods: once a month's key is destroyed, its bodies are gone in every copy.

## One purchase as a bundle

```sh
evidencestore proof -config store.json -source shop-agent -subject p-1002 -from FROM -to TO -out p-1002.json
esverify -proof p-1002.json -store-key store.pub -tsa-trust tsa-root.crt -gateway-key platform.pub -bodies p-1002/
python3 scripts/purchase-report.py -proof p-1002.json -store-key store.pub -tsa-trust tsa-root.crt -purchase p-1002 -gateway-key platform.pub -mandate-key customer.pub
```

`FROM` and `TO` (RFC 3339, the store's receive time) must cover the purchase from its mandate to its last step. The window is closed by a time-stamp taken more than two minutes after `TO`, and the bundle is ready one time-stamp later ([Bundles, One subject](bundles.md)). `purchase-report.py` runs `esverify` itself and prints the purchase only when the bundle verifies: the mandate, who the agent was, the cart against the mandate, the notice and the time left to cancel, the payment, the delivery, and where they disagree. A line under the purchase's label that the store found broken at intake, such as one added to the platform's log without its key, is not opened, and the report says so.

With `-mandate-key`, the public key (PEM) of whoever signed the mandate, the script checks the mandate's signature through `openssl`, and then compares the cart with what was signed, not with what the receipt next to it says: the price cap, the merchants, the expiry. It also says when the receipt differs from what was signed, and when the signed mandate names another purchase. Without the key, or for a credential in another form, the report says that the signature was not checked, and the mandate is the platform's word.

## What a purchase bundle proves, and what it does not

Proven, by `esverify` and without trusting the store or the platform:

- every receipt of the window under the purchase's label, byte for byte, and that the store received each one between two TSA time-stamps;
- with `-gateway-key`, that the platform signed every one of them;
- that no receipt of the source in the window is left out of the bundle. A cancellation, a second cart or a failed check cannot be dropped from the answer: a bundle with one of the purchase's receipts removed does not verify, and a closed receipt between two open ones is named by the signed `prev` of the next;
- nothing about other purchases is opened: their receipts travel encrypted and without keys.

Not proven:

- **That a receipt is true, or that every step was written.** The platform writes and signs the receipts. A step it never wrote is not in the store, and nothing in a bundle shows that it is missing.
- **That every receipt of the purchase is under its label.** The store sets the label when it receives a receipt, from its `action`; a receipt that names another purchase is not in this bundle ([Bundles](bundles.md) says what a store dishonest at intake could do).
- **Whose keys these are.** The platform's gateway key and the customer's key are for you to establish: a key the platform hands you proves nothing against the platform.
- **Any signature inside a receipt but the mandate's**, and the mandate's only as a compact JWS with ES256. An SD-JWT with disclosures and key binding, which is how AP2 carries mandates, is not parsed, and neither is the agent's signature: check those yourself, from the bodies `esverify -bodies` writes.
- **Who pays.** A bundle is evidence of what was recorded and when. Whether it settles a dispute is decided by the rules of the payment method and by whoever applies them.

Limits to plan for:

- **The bundle grows with the whole source, not with the purchase.** It carries every record the source wrote in the window, the other purchases' as encrypted evidence, and one bundle spans at most 250 000 leaves of the chain. Ask for a narrow window, and for a purchase that runs for days, window by window.
- **The other purchases stay closed, not invisible.** Of each of their receipts the bundle shows the number, the receive time, the length, a label and the store's verdict on it (the platform's chain, not the purchase), so the receipts of one unnamed purchase can be told from another's within a month.
- **Erasure is by source and month.** One customer's receipts cannot be destroyed apart from the rest of the month ([Keys and retention](keys.md)).
- **One source, one bundle.** A purchase recorded by two sources, the agent platform and the merchant or the payment network, takes a bundle from each; labels of different sources do not match. The platform's payment receipt names the network's reference in `refs`, so the two can be put side by side; this release does not check them as one.

## Try it

```sh
scripts/demo-purchase.sh                       # builds everything, runs offline, takes about three minutes; needs openssl
ES_BIN=/usr/local/bin scripts/demo-purchase.sh # the same on installed binaries
```

An agent makes three purchases through one platform, each under a mandate signed with its customer's key, and the platform signs a receipt for every step. Someone who can write the platform's log but has no key adds a cancellation of the second purchase. The script asks the store for the bundle of the second purchase, verifies it with the platform's key, shows that the receipts of the other two stay closed and that the added line is not opened, and prints the report with the mandate checked under the customer's public key; under another customer's key the signature does not verify. Then it changes one byte of the cart and, in another copy, takes the notification out of the bundle: neither copy verifies.
