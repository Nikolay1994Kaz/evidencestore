package store

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/metrics"
)

// Показатели отражают то, на что ставят тревоги: записи и повторы по
// источникам, поломки журнала гейтвея, ошибки приёма, метку TSA.
func TestMetrics(t *testing.T) {
	c := newClock()
	cfg := testConfig(t, withGateway(pipelockKey(t)))
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	ingest(t, s, "abs-core", 3, 3) // повтор
	ingestLines(t, s, 1, readLines(t, filepath.Join(pipelockVectors, "tampered.jsonl"))[:4])
	if _, err := s.Ingest("nope", []Incoming{{Seq: 1, Body: []byte("x")}}); err == nil {
		t.Fatal("чужой источник принят")
	}
	mustStamp(t, s)

	var b strings.Builder
	if err := metrics.Write(&b, s.Metrics(c.now())); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`evidencestore_up 1`,
		`evidencestore_records{source="abs-core"} 3`,
		`evidencestore_records{source="agent-gw"} 4`,
		`evidencestore_records_duplicate_total{source="abs-core"} 1`,
		`evidencestore_records_conflict_total{source="abs-core"} 0`,
		`evidencestore_epoch_refused_total{source="abs-core"} 0`,
		`evidencestore_gateway_problems_total{source="agent-gw"} 1`,
		`evidencestore_ingest_errors_total 1`,
		`evidencestore_log_failed 0`,
		`evidencestore_keyring_backup_pending 0`,
		`evidencestore_sign_key_backup_pending 0`,
		`evidencestore_keyring_orphan_roots 0`,
		`evidencestore_keyring_roots_unreachable 0`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("нет %q", want)
		}
	}
	for _, zeroNot := range []string{"evidencestore_tsa_last_stamp_timestamp_seconds ", "evidencestore_log_commits_total "} {
		if strings.Contains(out, zeroNot+"0\n") || !strings.Contains(out, zeroNot) {
			t.Errorf("%s: ноль или нет показателя", zeroNot)
		}
	}
	if t.Failed() {
		t.Log(out)
	}
}
