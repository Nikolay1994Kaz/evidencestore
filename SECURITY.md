# Security policy

## Reporting a vulnerability

Report it privately, through GitHub: the repository's **Security** tab → **Report a vulnerability**. Please do not open a public issue or pull request for it.

A useful report names the version or commit, what an attacker needs (which keys, which host, which files or network position), the steps or a test that shows the effect, and what `esverify` or the store reports while it happens.

## What counts

What the store and `esverify` promise, and what they do not, is in the README ([What is proven, and what is not](README.md#what-is-proven-and-what-is-not)) and in [Known limitations](docs/limitations.md). A vulnerability is a way around those promises, for example:

- a forged, rewritten or truncated chain, or a bundle that leaves something out, that `esverify` reports as VERIFIED;
- a time-stamp of a TSA key revoked for compromise that counts without a proof that it existed earlier;
- confirmed evidence lost or changed without the store or `esverify` showing it;
- a destroyed month key, or a body sealed under it, recovered without a copy of the old root key;
- input that crashes or stalls the store, a collector, a witness or `esverify`.

A limit already described in [docs/limitations.md](docs/limitations.md) is not a vulnerability, unless the report shows it reaches further than described there.

## Supported versions

Fixes go to `master` and the next release. Older releases are not patched: upgrade to the latest one ([docs/configuration.md](docs/configuration.md) says what each upgrade changes).

## Checking a release

Every release carries `SHA256SUMS` and a build provenance attestation made by the release workflow:

```
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify evidencestore-linux-amd64 --repo Nikolay1994Kaz/evidencestore
```
