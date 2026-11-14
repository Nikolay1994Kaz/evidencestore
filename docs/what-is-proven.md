# What is proven, and what is not

[← README](../README.md)

What a bundle that `esverify` reports as VERIFIED proves, which flags add what, and what no bundle proves. The limits of the product as a whole are in [Known limitations](limitations.md).

Proven offline:

- these exact bytes were received from this source;
- they have not been altered since;
- they entered the chain between the two time-stamps T1 and T2;
- with the collector's promise (`esverify -promise`): the store signed for this very record at intake, and no TSA time-stamp taken more than a minute after its receive time lies before the record in the chain;
- with the record key: the body as received (`esverify -body FILE` writes it out byte for byte, so the original log can be rebuilt from the store); the key is bound to the record's digest, so the store cannot show two auditors two different bodies;
- for gateway journals: the body is the gateway's own entry, and a checkpoint signed by the gateway covers it — when that signature was checked by the store with the pinned `gateway_key` or by you with `-gateway-key`. A gateway record whose bundle lacks the gateway part does not verify;
- with `-heads DIR`: the chain in the bundle agrees with every head a witness holds for that part of the chain — the store's witness or a collector's head journal; two versions of a head elsewhere, and heads a collector refused, are named in the report (see [Witness of the chain heads](copy-and-witness.md#witness-of-the-chain-heads));
- with `-seal-trust CA -seal-subject ATTR=VALUE` instead of `-store-key`: the store key is the one the organization you name sealed with its X.509 certificate under that CA (a seal or a legal entity's signature certificate), and the certificate was in force when the seal was time-stamped; then you need the CA's root and the organization's name, not a key from the store's operator (see [A seal on the store key](keys.md#a-seal-on-the-store-key));
- with `-witness-key VKEY` for each witness you name: that witness signed a head at or after the record at the time its cosignature names, and the chain in the bundle agrees with that head; a witness cosigns only heads that extend every head it cosigned before, so a later rewrite of that part of the chain contradicts it (see [Cosigning witnesses](copy-and-witness.md#cosigning-witnesses-c2sp));
- with a bundle over a window of time (`evidencestore proof -source S -from FROM -to TO`, or `-window` for every source): every record the store put into its chain between two TSA time-stamps is in the bundle, so a record received in the window cannot be kept from the auditor unless the store holds it back past the window, and then the deadline the store promised the collector for it is missed and `esverify -promise` shows it (see [Bundles over a window of time](bundles.md)). Only the records of the window open. When the source has `subject_field`, `-subject V` opens only the records under one subject's label, with the same proof that no record of the source is left out; which records are the subject's rests on the label the store set at intake. The window is by the store's receive time, which the collector checks against its own clock to within a minute, and that clock may run up to a minute ahead: this holds for records the collector delivered more than two minutes before the window ends.

T2 is required: a bundle without a time-stamp after the record only carries the store's own signature, and whoever holds `sign.key` can make up a record with any date. `esverify` rejects such a bundle unless told `-allow-no-tsa`. The verdict is printed first and last, and control characters in the body are escaped, so a body cannot paint a false verdict on the auditor's screen.

Not proven:

- that the content is true: a lying source is recorded faithfully;
- anything before the record reached the store;
- anything about records the source never wrote;
- from a single-record bundle, that you were given every record: it proves that one record only. A bundle over a window of time proves the whole window, by the store's receive time, not by the time written in the lines;
- from a one-source bundle, that the source tails are true: they are the store's own statements, written when it took the time-stamps, and an understated one shows in a window bundle or in the hidden record's own bundle;
- that a bundle over a window of time was built from the chain as it was then: a rewrite after the lower time-stamp needs fresh time-stamps after it. A T2 more than an hour after the window is a sign of that (the store takes a time-stamp at least once an hour); a rewrite made sooner is caught only by a witness, with `-witness-key` or `-heads`; the latter takes, for each witness, the head it received first when the heads directory holds the S3 versions list or a collector's head journal (see [Witness of the chain heads](copy-and-witness.md#witness-of-the-chain-heads)).

Root on the store host can delete or rewrite the store's files, and whoever holds `sign.key` can sign a second version of the chain. That leaves traces: a rewritten chain gets only fresh time-stamps, the collectors hold signed promises for the original records (`esverify -promise` shows a replaced one) and notice that the store's heads stop extending the one they hold, and a witness or a remote copy kept out of that administrator's reach still holds the original signed heads. The traces help only someone who checks them: a collector logs an error when a head does not extend the one it holds (and keeps both) or when for a while none does, `esverify -heads` compares a bundle with a witness's or a collector's heads, nothing compares the collectors' promises by itself, and nothing can prevent the rewrite. Keep the store, its remote copy and the sources under different administrators where you can. With one administrator for everything, only the time-stamps and a witness that administrator does not control stand against them. The pilot cryptography (AES-256-GCM from the Go standard library, root keys in files) is not certified. The design keeps a plug-in point for an HSM.

## Exit codes of `esverify`

- `0`: verified.
- `1`: not verified, including an unparsable bundle or a broken promise.
- `2`: bad usage (including a flag meant for the other kind of bundle, or a bad `-from` or `-to`); an unreadable bundle, key, certificate or promise file or heads directory; `-body` for a bundle without the record key; `-bodies` for a bundle that opens no body though the window holds records.

A window with no records, with none under the subject's label, or with records only in months the bundle names no label for, is an answer: `-bodies` says so, and the exit code is 0.

`-body FILE` writes the record body to a file byte for byte, only once the bundle verifies. A bundle over a window of time (`evidencestore proof -source S -from -to`, or `-window` for every source) is checked for completeness, and `-bodies DIR` writes out the bodies it carries.
