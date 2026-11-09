package store

import (
	"sort"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/metrics"
)

// Metrics — показатели для /metrics. Счётчики — с запуска процесса
// (Prometheus переживает их сброс), остальное читается из состояния в
// момент запроса. На что ставить тревоги — docs/monitoring.md.
func (s *Store) Metrics(now time.Time) []metrics.Family {
	st := s.Status()
	ev := s.evlog.Stats()
	fams := []metrics.Family{
		metrics.One("evidencestore_up", "1 while the store runs", metrics.Gauge, 1),
		metrics.One("evidencestore_log_failed", "1 when the evidence log or the chain stopped after a write or fsync error; intake is refused until a human intervenes", metrics.Gauge, metrics.Bool(st.LogFailure != "")),
		metrics.One("evidencestore_chain_failed", "1 when the chain stopped after a write or fsync error; intake is refused until a human intervenes", metrics.Gauge, metrics.Bool(st.ChainFailure != "")),
		metrics.One("evidencestore_receive_clock_capped_total", "receive times kept within the TSA window because the host clock ran ahead of TSA time or behind it", metrics.Counter, float64(s.clockCapped.Load())),
		metrics.One("evidencestore_receive_time_ahead_seconds", "how far the last receive time is ahead of the host clock (an earlier clock jump), 0 if not", metrics.Gauge, s.receiveAhead(now)),
		metrics.One("evidencestore_log_commits_total", "batches written to the evidence log with fsync", metrics.Counter, float64(ev.Commits)),
		metrics.One("evidencestore_log_commit_seconds_total", "time spent writing and fsyncing evidence log batches", metrics.Counter, float64(ev.CommitNanos)/1e9),
		metrics.One("evidencestore_ingest_errors_total", "ingest requests that failed", metrics.Counter, float64(s.ingestErrors.Load())),
		metrics.One("evidencestore_keyring_backup_pending", "1 when the last keyring.dat write has not reached keys.backup_dir; new month keys are not issued and key receipts wait", metrics.Gauge, metrics.Bool(st.KeyringBackupPending)),
		metrics.One("evidencestore_sign_key_backup_pending", "1 when sign.key is not confirmed in keys.backup_dir: the copy failed, or another key lies there", metrics.Gauge, metrics.Bool(st.SignKeyBackupPending)),
		metrics.One("evidencestore_copy_key_backup_pending", "1 when copy.key is not confirmed in keys.backup_dir: the copy failed, or another key lies there; nothing is copied meanwhile", metrics.Gauge, metrics.Bool(st.CopyKeyBackupPending)),
		metrics.One("evidencestore_keyring_orphan_roots", "keyring roots unknown to keyring.dat; key destruction is not final while any exist", metrics.Gauge, float64(len(st.OrphanRoots))),
		metrics.One("evidencestore_keyring_roots_unreachable", "1 when the keyring root directories cannot be listed (keys.roots_mirror_dir down?); key destruction is not final meanwhile", metrics.Gauge, metrics.Bool(st.RootsUnreachable != "")),
		metrics.One("evidencestore_keys_due", "source months past retention whose keys wait for a destruction request", metrics.Gauge, float64(len(s.RetentionDue(now)))),
		metrics.One("evidencestore_chain_head", "sequence number of the chain head", metrics.Gauge, float64(st.HeadSeq)),
		metrics.One("evidencestore_tsa_last_stamp_timestamp_seconds", "generation time of the last TSA token in the chain, 0 if none", metrics.Gauge, seconds(st.LastStamp)),
		metrics.One("evidencestore_tsa_errors_total", "failed time-stamp attempts", metrics.Counter, float64(s.stampErrors.Load())),
		metrics.One("evidencestore_replica_last_success_timestamp_seconds", "end of the last successful copy to replica.url, 0 if none since start", metrics.Gauge, seconds(time.Unix(0, s.replicaOK.Load()))),
		metrics.One("evidencestore_replica_errors_total", "failed copy attempts", metrics.Counter, float64(s.replicaErrors.Load())),
		metrics.One("evidencestore_replica_cosign_journal_skipped", "1 when data_dir/cosign/cosignatures.jsonl does not continue the one in the copy (removed or replaced): the copy goes on without new witness cosignatures until replica.url points at a new location", metrics.Gauge, metrics.Bool(s.cosignSkipped.Load())),
		metrics.One("evidencestore_replica_archive_journal_skipped", "1 when data_dir/tsa/archive.jsonl does not continue the one in the copy (removed or replaced): the copy goes on without new time-stamps of the second TSA until replica.url points at a new location", metrics.Gauge, metrics.Bool(s.archiveSkipped.Load())),
		metrics.One("evidencestore_witness_last_success_timestamp_seconds", "when the last signed head reached witness.url, 0 if none since start", metrics.Gauge, seconds(time.Unix(0, s.witnessOK.Load()))),
		metrics.One("evidencestore_witness_errors_total", "failed attempts to send a signed head to witness.url", metrics.Counter, float64(s.witnessErrors.Load())),
	}
	records := metrics.Family{Name: "evidencestore_records", Help: "records of the source in the evidence log", Type: metrics.Gauge}
	last := metrics.Family{Name: "evidencestore_source_last_record_timestamp_seconds", Help: "receive time of the source's last record, 0 if none", Type: metrics.Gauge}
	silent := metrics.Family{Name: "evidencestore_source_silent", Help: "1 when the source has been silent longer than its expect_every", Type: metrics.Gauge}
	lost := metrics.Family{Name: "evidencestore_source_contact_lost", Help: "1 when the source's collector has not contacted the store (a batch or a heartbeat) for longer than its expect_contact: stopped, crashed, host down or network cut", Type: metrics.Gauge}
	contact := metrics.Family{Name: "evidencestore_source_last_contact_timestamp_seconds", Help: "when the source's collector last contacted the store, 0 if not since start", Type: metrics.Gauge}
	dups := metrics.Family{Name: "evidencestore_records_duplicate_total", Help: "records resent by the source that had already been accepted", Type: metrics.Counter}
	conflicts := metrics.Family{Name: "evidencestore_records_conflict_total", Help: "records resent under a taken seq with another body: a collector rolled back to an old copy, or two collectors with one certificate", Type: metrics.Counter}
	epochs := metrics.Family{Name: "evidencestore_epoch_refused_total", Help: "requests refused because another collector installation (another epoch) uses the source certificate", Type: metrics.Counter}
	noSubject := metrics.Family{Name: "evidencestore_records_without_subject_total", Help: "records of a source with subject_field that name no subject, since the store started: they carry no label and stay closed in subject bundles", Type: metrics.Counter}
	gw := metrics.Family{Name: "evidencestore_gateway_problems_total", Help: "gateway journal entries that were not intact at intake: hash, linkage or checkpoint signature", Type: metrics.Counter}
	s.mu.Lock()
	names := make([]string, 0, len(s.sources))
	for name := range s.sources {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		src := s.sources[name]
		l := [][2]string{{"source", name}}
		records.Samples = append(records.Samples, metrics.Sample{Labels: l, Value: float64(src.count)})
		last.Samples = append(last.Samples, metrics.Sample{Labels: l, Value: seconds(src.lastAt)})
		silent.Samples = append(silent.Samples, metrics.Sample{Labels: l, Value: metrics.Bool(src.silent)})
		lost.Samples = append(lost.Samples, metrics.Sample{Labels: l, Value: metrics.Bool(!src.lostSince.IsZero())})
		contact.Samples = append(contact.Samples, metrics.Sample{Labels: l, Value: seconds(src.contactAt)})
		dups.Samples = append(dups.Samples, metrics.Sample{Labels: l, Value: float64(src.dups.Load())})
		conflicts.Samples = append(conflicts.Samples, metrics.Sample{Labels: l, Value: float64(src.conflicts.Load())})
		epochs.Samples = append(epochs.Samples, metrics.Sample{Labels: l, Value: float64(src.epochRefused.Load())})
		if src.cfg.SubjectField != "" {
			noSubject.Samples = append(noSubject.Samples, metrics.Sample{Labels: l, Value: float64(src.noSubject.Load())})
		}
		if src.gw != nil {
			gw.Samples = append(gw.Samples, metrics.Sample{Labels: l, Value: float64(src.gwProblems.Load())})
		}
	}
	s.mu.Unlock()
	fams = append(fams, records, last, silent, lost, contact, dups, conflicts, noSubject, epochs, gw)
	if len(st.Cosigners) > 0 {
		head := metrics.Family{Name: "evidencestore_cosigner_head", Help: "the last head the C2SP witness cosigned for this store, 0 if none known", Type: metrics.Gauge}
		ok := metrics.Family{Name: "evidencestore_cosigner_last_success_timestamp_seconds", Help: "when the C2SP witness last returned a cosignature that verified (after a start: the time its last cosignature in the journal carries), 0 if none", Type: metrics.Gauge}
		errs := metrics.Family{Name: "evidencestore_cosigner_errors_total", Help: "failed rounds of sending heads to the C2SP witness", Type: metrics.Counter}
		refused := metrics.Family{Name: "evidencestore_cosigner_refused", Help: "1 when the C2SP witness refused the consistency proof from the last head it cosigned: it holds another history of this store's chain", Type: metrics.Gauge}
		lost := metrics.Family{Name: "evidencestore_cosigner_lost_state", Help: "1 when the C2SP witness reports an older head than it cosigned for this store: it lost its state and would cosign a second history under the same key", Type: metrics.Gauge}
		for _, c := range st.Cosigners {
			l := [][2]string{{"witness", c.Name}}
			head.Samples = append(head.Samples, metrics.Sample{Labels: l, Value: float64(c.Head)})
			ok.Samples = append(ok.Samples, metrics.Sample{Labels: l, Value: seconds(c.LastAt)})
			errs.Samples = append(errs.Samples, metrics.Sample{Labels: l, Value: float64(c.Errors)})
			refused.Samples = append(refused.Samples, metrics.Sample{Labels: l, Value: metrics.Bool(c.Refused)})
			lost.Samples = append(lost.Samples, metrics.Sample{Labels: l, Value: metrics.Bool(c.LostState)})
		}
		fams = append(fams, head, ok, errs, refused, lost)
	}
	if a := st.TSAArchive; a != nil {
		fams = append(fams,
			metrics.One("evidencestore_tsa_archive_head", "the last head the second TSA (tsa.archive) time-stamped, 0 if none", metrics.Gauge, float64(a.Head)),
			metrics.One("evidencestore_tsa_archive_last_success_timestamp_seconds", "when the second TSA last returned a time-stamp that verified, 0 if none since start", metrics.Gauge, seconds(a.LastAt)),
			metrics.One("evidencestore_tsa_archive_errors_total", "failed attempts to get a time-stamp of the second TSA", metrics.Counter, float64(a.Errors)))
	}
	return fams
}

// receiveAhead — насколько последнее время приёма впереди часов хоста.
func (s *Store) receiveAhead(now time.Time) float64 {
	s.mu.Lock()
	last := s.lastRecv
	s.mu.Unlock()
	return max(0, float64(last-now.UnixNano())/1e9)
}

func seconds(t time.Time) float64 {
	if t.IsZero() || t.UnixNano() <= 0 {
		return 0
	}
	return float64(t.UnixNano()) / 1e9
}
