# How it was tested

[← README](../README.md)

Numbers below are for commit `957345c` (12 October 2026), unless a later date is given.

- **Test gate.** `go build ./... && go vet ./... && go test -race ./...` passes.
- **Mutation testing** (28–29 October 2026, on the code of v0.3.0). 578 bugs injected one at a time (`scripts/mutations/`), and every one of them makes a test fail: store and proofs 344, collector and intake 85, keyring 62, evidence log 21, gateway journals 15, chain 15, TSA 14, configuration 16, copy transport 6. Six of them survived the first run: what they broke (the shape of the chain after a crash and around a time-stamp, receive times around a time-stamp and after a host clock step) no longer carries the promise check, and the tests saw it only through that check; tests now read it from the chain itself (Q-84 in [`docs/dev/FINDINGS.md`](dev/FINDINGS.md)).
- **Simulations:** randomized scenarios checked against an oracle (commands under Development).
  - Store with crashes: 2,000 scenarios of 300 steps, no failures. They went through 36,038 crashes (3,848 in the middle of a write), 6,649 restores from the copy (1,154 after the disk was lost in the middle of a copy pass), 1,368 disks that lied about fsync, 2,185 destroyed keys (231 crashes in the middle of a root rotation) and 75,858 rounds of parallel intake (1.25 million batches, 312,900 pairs of identical concurrent requests). 300 more scenarios under the race detector found no data race. Later, on 17 October, CI caught a data race in the simulation's own bookkeeping (test code, not the store); it is fixed (Z-12 in [`docs/dev/FINDINGS.md`](dev/FINDINGS.md)).
  - Receive-time clock: 3,000 scenarios, no failures.
  - Collector: 2,000 scenarios in each of four worlds (one file or a glob, with and without destruction) against an in-memory store, 150 per world against the real store over mTLS, and 400 per world against the real store with all faults at once; no failures.
  - On 27 October, on the code of the bundles over a window of time: store with crashes 1,500 scenarios of 300 steps and the receive-time clock 2,000 scenarios, no failures; the collector 2,000 scenarios in each of four worlds and 200 per world against the real store, with one failure in a world with destruction (a gap the collector left reached the store only with the next record; fixed the same day: the heartbeat carries the last issued number, and the scenario passes).
  - On 27 October, evening, after the third review round: store with crashes 1,500 scenarios of 300 steps and the collector 2,000 scenarios per world and 200 against the real store, no failures; the receive-time clock run of 2,000 scenarios failed 226 on a fault in the simulation's own check (two time-stamps in one second after a restart), and after that was fixed 300 scenarios ran with no failures. A new simulation of a dishonest store owner (`TestOwnerSim`: held-back records and tokens, copies of old tokens, links dated back as far as the checks allow, shifted receive times) found that a receive time shifted forward hid a record from the window bundle with its promise kept; the collector now checks receive times.
  - On 28 October, on the code of v0.3.0, with the collector's promise checked against the time-stamps: store with crashes 2,000 scenarios of 300 steps, through 37,307 crashes (4,186 in the middle of a write), 6,727 restores from the copy (1,104 after the disk was lost in the middle of a copy pass), 1,395 disks that lied about fsync, 1,322 destroyed keys (138 crashes in the middle of a root rotation), 75,653 rounds of parallel intake (1.25 million batches, 313,129 pairs of identical concurrent requests) and 56,296 episodes of a lost collector; a dishonest store owner 2,000 scenarios, in which each of the 632 window bundles that left a record out was exposed by that record's promise; the receive-time clock 1,000 scenarios; the collector 2,000 scenarios in each of four worlds and 150 per world against the real store; no failures. On the release candidate with test hooks: an upgrade from v0.2.0 with `kill -9` during intake (all 632 promises verify) and an evidence log whose fsync fails (no time-stamp until restart, then all 244 promises verify).
- **Live gateway.** `scripts/demo-pipelock.sh` passes against Pipelock v3.6.0 built from the tag's commit.
- **A night on real data** (11–12 October, 21:19–06:23). The store ran with four collectors: the host's own `/var/log/syslog`, `auth.log` and `kern.log` (read from the start), and the flight recorder of a live Pipelock v3.6.0 that blocked an "agent" all night (no request left the host). During the night logrotate rotated all three logs at midnight (`create`, `delaycompress`, rsyslog HUP), the store was restarted 5 times, a collector was killed with `kill -9`, Pipelock was restarted twice (3 sessions, 359 shards), and the copy went to a directory every minute. Every one of the 104,738 records matched its source line, in order, with no duplicates and no losses: syslog 71,120 (67,596 from the rotated file, 3,524 from the new one), auth.log 1,246, kern.log 10,752, Pipelock 21,620. A sample of 7,560 proof bundles across the whole range verified the way `esverify` does, the Pipelock ones with the gateway's checkpoint signature. A store restored from the copy (76 MB, chain checked up to signed head 8005) gave the same result. The store log had no errors. The scripts of this run were a one-off and are not in the repository.
- **Witness and copy on real S3** (25 October, MinIO RELEASE.2025-10-15 with Object Lock in compliance mode). The store sent its signed heads to a locked bucket and its copy to another; `esverify -heads` verified a bundle against all versions of the witnessed heads, a junk version and a delete marker put over a head afterwards changed nothing, and `restore` from the copy passed. A one-off run; AWS itself was not tried.

## Simulations

```sh
SIM_SEEDS=1000 go test -timeout 0 -run TestCollectorSim ./internal/collector/   # collector simulation: rotations (dateext too),
                                      # renames, restarts and crashes before, after and in the middle of a write, long lines,
                                      # lost store answers, permissions, destruction — every line once, or a visible gap
SIM_REAL_SEEDS=100 go test -timeout 0 -run 'TestCollectorSim/real' ./internal/collector/ # the same against the real store
                                      # over mTLS: every record's proof verifies, every gap is a chain event
CLOCKSIM_SEEDS=1000 go test -timeout 0 -run TestClockSim ./internal/store/       # receive-time simulation: clocks off, drifting,
                                      # jumping; slow, absent TSA; idle days; a suspended host; a record still
                                      # being written while a time-stamp is taken — every accepted record verifies
                                      # and keeps its promise
ADVSIM_SEEDS=1000 go test -timeout 0 -run TestOwnerSim ./internal/proof/         # a dishonest store owner: held-back records and tokens,
                                      # copies of old tokens, backdated links, shifted receive times, long
                                      # deadlines — every record of a window is in each window and one-source
                                      # bundle that verifies, or its promise shows the missed deadline
STORESIM_SEEDS=1000 go test -timeout 0 -run TestStoreCrashSim ./internal/store/  # store crashes at every write point (chain leaves,
                                      # link, head; key backup; root rotation; before the answer; torn writes), keyring.dat
                                      # restored from backup, key destruction, segment rotation, a disk that lies about
                                      # fsync, disk loss and restore from the copy (also mid-copy), a restart minutes
                                      # after the crash, parallel intake with
                                      # duplicate requests — every promise kept, every record once, every gap in the chain,
                                      # everything copied by a finished pass back after a restore
```

`go test` runs the simulations with a few dozen scenarios each; a failure prints `SIM_SEED=` (`CLOCKSIM_SEED=`, `ADVSIM_SEED=`, `STORESIM_SEED=`), which replays that scenario with its full trace (a store scenario with parallel intake replays its steps, not the exact interleaving). Every collector scenario draws its own set of faults; `SIM_FAULTS=all` (or a comma list: `long,after,torn,flaky,perm-new,perm-file,perm-dir,perm-spool,dateext`) fixes it.
