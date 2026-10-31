# Monitoring

[← README](../README.md)

Set `metrics_listen` (for example `127.0.0.1:9464`) to expose `/metrics` in the Prometheus text format. Worth an alert:

| Condition | Meaning |
|---|---|
| `evidencestore_log_failed == 1` | the evidence log or the chain stopped after a write or fsync error; intake is refused until a human looks (`evidencestore_chain_failed` tells which), and no time-stamp is taken until the store restarts: a batch whose fsync failed may still be on disk, and the restart writes the records not yet in the chain to disk again (a failed fsync leaves them only in the page cache) and puts them into the chain before any new time-stamp; if that write fails, the store does not start |
| `increase(evidencestore_receive_clock_capped_total[1h]) > 0` | the host clock runs ahead of TSA time, or lags behind it by about a minute, or the monotonic clock stood still (the host was suspended, the VM paused) until the next time-stamp; receive times are held inside the window known from the last time-stamp and the monotonic clock |
| `evidencestore_receive_time_ahead_seconds > 60` | the log holds receive times ahead of the host clock (an earlier clock jump) |
| `evidencestore_keyring_backup_pending == 1` for 10 minutes | `keyring.dat` changes are not reaching `keys.backup_dir`; new month keys are not issued |
| `evidencestore_sign_key_backup_pending == 1` for 10 minutes | `sign.key` is not confirmed in `keys.backup_dir`: the directory is missing (an unmounted disk?) or unwritable, or another key lies there (the log says which); after losing `data_dir` the store could not sign as itself |
| `time() - evidencestore_tsa_last_stamp_timestamp_seconds > 3600 + 2 × tsa.every` | time-stamps are not landing (with nothing new in the chain the store stamps only once an hour; `increase(evidencestore_tsa_errors_total[30m]) > 0` shows failed attempts sooner) |
| `time() - evidencestore_replica_last_success_timestamp_seconds > 3 × replica.every` for `2 × replica.every` | the copy is falling behind (the gauge is 0 after a start until the first pass): the remote is down or its `file://` directory is missing, or the store refuses a copy that `data_dir` does not continue (see [Copy and restore](copy-and-witness.md#copy-and-restore)) |
| `increase(evidencestore_witness_errors_total[10m]) > 0` | signed heads do not reach `witness.url`; they wait in memory, and heads under time-stamps queued before a restart are not resent |
| `evidencestore_source_silent == 1` | a source has been quiet longer than its `expect_every` |
| `evidencestore_source_contact_lost == 1` | a source's collector has not contacted the store (a batch or a heartbeat) for longer than its `expect_contact`: stopped, crashed or hung, its host down, or the network cut; the chain marks the window |
| `increase(evidencestore_gateway_problems_total[1h]) > 0` | a gateway journal entry was broken, out of order or badly signed |
| `increase(evidencestore_epoch_refused_total[1h]) > 0` | another collector installation used the source certificate and was refused: an impostor, or a reinstall waiting for `sources bind` |
| `increase(evidencestore_records_conflict_total[1h]) > 0` | a resend was refused: another body under a taken number (a spool restored from an old copy, or two collectors share one certificate), or a body that cannot be compared (month key pending destruction or destroyed); the reason is in the chain event and in the collector log |
| `evidencestore_keys_due > 0` | months past retention wait for a destruction request (two approvals) |
| `evidencestore_keyring_orphan_roots > 0` | key destruction is not final until orphan roots are dealt with |
| `evidencestore_keyring_roots_unreachable == 1` | the root directories cannot be listed (`keys.roots_mirror_dir` down?); key destruction is not final meanwhile |
| `rate(evidencestore_ingest_errors_total[5m]) > 0` | ingest requests are failing |

Also exported: records, duplicates and conflicts per source, evidence-log batches and their fsync time, the chain head.
