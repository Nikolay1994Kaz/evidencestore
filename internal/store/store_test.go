package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"evidencestore/internal/auditchain"
	"evidencestore/internal/config"
	"evidencestore/internal/evidence"
	"evidencestore/internal/keyring"
	"evidencestore/internal/proof"
	"evidencestore/internal/ship"
)

// clock — подвижные часы теста.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }
func (c *clock) set(t time.Time)     { c.mu.Lock(); c.t = t; c.mu.Unlock() }

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func testConfig(t *testing.T, opts ...func(*config.Config)) *config.Config {
	t.Helper()
	cfg := &config.Config{
		DataDir:  filepath.Join(t.TempDir(), "data"),
		RootsDir: filepath.Join(t.TempDir(), "roots"),
		TSA:      config.TSA{URL: "local"},
		Keys:     config.Keys{MinWait: config.Duration(time.Nanosecond)},
		Sources: []config.Source{
			{Name: "abs-core", ContentType: "syslog", RetentionMonths: 1, ExpectEvery: config.Duration(10 * time.Minute)},
			{Name: "pipelock", ContentType: "pipelock/receipt"},
		},
	}
	for _, o := range opts {
		o(cfg)
	}
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func openStore(t *testing.T, cfg *config.Config, c *clock) *Store {
	t.Helper()
	s, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newClock() *clock { return &clock{t: time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)} }

func ingest(t *testing.T, s *Store, source string, from, to uint64) []Result {
	t.Helper()
	var recs []Incoming
	for q := from; q <= to; q++ {
		recs = append(recs, Incoming{Seq: q, Body: []byte(fmt.Sprintf("%s event %d", source, q))})
	}
	res, err := s.Ingest(source, recs)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func trustOf(t *testing.T, s *Store) proof.Trust {
	t.Helper()
	pub, err := base64.RawStdEncoding.DecodeString(s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return proof.Trust{StoreKey: ed25519.PublicKey(pub), TSA: s.TSATrust()}
}

func mustStamp(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.Stamp(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// copyDirs — снимок дисков «на ходу», как они лежат в момент падения:
// журнал улик уже на диске (fsync), листья цепи ещё в памяти.
func copyDirs(t *testing.T, cfg *config.Config) *config.Config {
	t.Helper()
	out := *cfg
	out.DataDir = filepath.Join(t.TempDir(), "data")
	out.RootsDir = filepath.Join(t.TempDir(), "roots")
	for src, dst := range map[string]string{cfg.DataDir: out.DataDir, cfg.RootsDir: out.RootsDir} {
		if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
			t.Fatal(err)
		}
	}
	out.AdminSocket = ""
	out.Defaults()
	return &out
}

func leavesOf(t *testing.T, cfg *config.Config, typ auditchain.EventType) []auditchain.Leaf {
	t.Helper()
	var out []auditchain.Leaf
	_, chainDir, _ := dirs(cfg)
	if err := auditchain.ScanLeaves(chainDir, func(_ uint64, l auditchain.Leaf) error {
		if l.Type == typ {
			out = append(out, l)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// ⭐ Полный путь: приём → метки TSA → пакет доказательств → офлайн-проверка
// с телом, вскрытым ключом одной записи.
func TestIngestProofVerify(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)

	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s) // T1 для улик, что придут дальше
	c.add(time.Minute)
	res := ingest(t, s, "abs-core", 4, 6)
	if res[1].Status != StatusAccepted || res[1].Promise == nil {
		t.Fatalf("приём: %+v", res[1])
	}
	c.add(time.Minute)
	mustStamp(t, s) // T2

	b, err := s.Proof("abs-core", 5, true)
	if err != nil {
		t.Fatal(err)
	}
	if b.Lower == nil || b.Upper == nil {
		t.Fatalf("в пакете нет меток: lower=%v upper=%v", b.Lower != nil, b.Upper != nil)
	}
	r := proof.Verify(b, trustOf(t, s))
	if !r.Valid() {
		t.Fatalf("пакет не прошёл:\n%s", r.Text())
	}
	if string(r.Body) != "abs-core event 5" || r.Header.Seq != 5 || r.Lower.IsZero() || r.Upper.IsZero() {
		t.Fatalf("отчёт:\n%s", r.Text())
	}
	// Обещание при приёме сходится с тем, что в цепи.
	p := *res[1].Promise
	if err := proof.VerifyPromise(p, trustOf(t, s).StoreKey); err != nil {
		t.Fatal(err)
	}
	var linkTime int64
	for _, l := range b.Links {
		if l.Seq == r.LinkSeq {
			linkTime = l.UnixNano
		}
	}
	if err := proof.CheckPromise(p, r, linkTime); err != nil {
		t.Fatal(err)
	}
	// Ключ записи — только по просьбе.
	if nb, err := s.Proof("abs-core", 5, false); err != nil || len(nb.DEK) != 0 {
		t.Fatalf("ключ записи выдан без просьбы: %d байт, %v", len(nb.DEK), err)
	}
	// Пакет переживает JSON.
	data, _ := b.JSON()
	b2, err := proof.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if r2 := proof.Verify(b2, trustOf(t, s)); !r2.Valid() {
		t.Fatalf("после JSON:\n%s", r2.Text())
	}
}

// Любая подмена в пакете проваливает проверку, и закреплённый ключ
// обязателен.
func TestTamperingIsDetected(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ingest(t, s, "abs-core", 1, 2)
	mustStamp(t, s)
	ingest(t, s, "abs-core", 3, 4)
	mustStamp(t, s)
	good, err := s.Proof("abs-core", 3, true)
	if err != nil {
		t.Fatal(err)
	}
	trust := trustOf(t, s)
	if r := proof.Verify(good, trust); !r.Valid() {
		t.Fatalf("исходный пакет:\n%s", r.Text())
	}
	clone := func() proof.Bundle {
		data, _ := good.JSON()
		b, _ := proof.Parse(data)
		return b
	}
	cases := map[string]func(*proof.Bundle){
		"байт улики":      func(b *proof.Bundle) { b.Evidence[len(b.Evidence)-1] ^= 1 },
		"время в улике":   func(b *proof.Bundle) { b.Evidence[10] ^= 1 },
		"лист":            func(b *proof.Bundle) { b.Inclusion.Leaf.Subject = "4" },
		"путь":            func(b *proof.Bundle) { b.Inclusion.Path[0].Hash[0] ^= 1 },
		"звено":           func(b *proof.Bundle) { b.Links[0].UnixNano++ },
		"выкинутое звено": func(b *proof.Bundle) { b.Links = append(b.Links[:1], b.Links[2:]...) },
		"голова":          func(b *proof.Bundle) { b.Statement.HeadSeq-- },
		"токен T2":        func(b *proof.Bundle) { b.Upper.Token[len(b.Upper.Token)/2] ^= 1 },
		"голова T2":       func(b *proof.Bundle) { b.Upper.HeadSeq = b.Inclusion.LinkSeq - 1 },
		"токен T1":        func(b *proof.Bundle) { b.Lower.Inclusion.Leaf.Payload[100] ^= 1 },
		"ключ записи":     func(b *proof.Bundle) { b.DEK[0] ^= 1 },
	}
	for name, mutate := range cases {
		// Без ключа записи: иначе часть подмен ловил бы тег GCM и прятал,
		// стерегут ли их сами проверки цепи.
		for _, withDEK := range []bool{true, false} {
			b := clone()
			if !withDEK {
				if name == "ключ записи" {
					continue
				}
				b.DEK = nil
			}
			mutate(&b)
			if r := proof.Verify(b, trust); r.Valid() {
				t.Errorf("%s (ключ записи: %v): подмена не замечена", name, withDEK)
			}
		}
	}
	other := testConfig(t)
	so := openStore(t, other, newClock())
	if r := proof.Verify(clone(), trustOf(t, so)); r.Valid() {
		t.Error("пакет прошёл с чужим ключом хранилища и чужой TSA")
	}
}

// Повтор безопасен: уже принятое отвечает «duplicate», в том числе после
// рестарта; сборщик после переустановки узнаёт последний номер.
func TestDuplicatesAndLastSeq(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	res := ingest(t, s, "abs-core", 2, 4)
	if res[0].Status != StatusDuplicate || res[1].Status != StatusDuplicate || res[2].Status != StatusAccepted {
		t.Fatalf("повторы: %+v", res)
	}
	if res[0].Promise != nil {
		t.Fatal("повтор получил новое обещание")
	}
	s.Close()
	s2 := openStore(t, cfg, c)
	if last, err := s2.LastSeq("abs-core"); err != nil || last != 4 {
		t.Fatalf("LastSeq: %d, %v", last, err)
	}
	if res := ingest(t, s2, "abs-core", 4, 5); res[0].Status != StatusDuplicate || res[1].Status != StatusAccepted {
		t.Fatalf("после рестарта: %+v", res)
	}
	for _, bad := range [][]Incoming{
		{{Seq: 0, Body: []byte("x")}},
		{{Seq: 9, Body: []byte("x")}, {Seq: 9, Body: []byte("y")}},
		{{Seq: 10, Body: make([]byte, evidence.MaxBodyLen+1)}},
	} {
		if _, err := s2.Ingest("abs-core", bad); !errors.Is(err, ErrBadRecord) {
			t.Fatalf("негодная пачка: %v", err)
		}
	}
	if _, err := s2.Ingest("intruder", []Incoming{{Seq: 1, Body: []byte("x")}}); !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("чужой источник: %v", err)
	}
}

// Падение после fsync журнала, до звена: улики на диске, листьев в цепи
// нет. Подъём досчитывает цепь по журналу, доказательства строятся.
func TestCrashCatchUp(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 2)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 3, 5) // листья в памяти, звена нет
	crashed := copyDirs(t, cfg)

	s2 := openStore(t, crashed, c)
	mustStamp(t, s2)
	for q := uint64(1); q <= 5; q++ {
		b, err := s2.Proof("abs-core", q, true)
		if err != nil {
			t.Fatalf("seq %d: %v", q, err)
		}
		if r := proof.Verify(b, trustOf(t, s2)); !r.Valid() {
			t.Fatalf("seq %d:\n%s", q, r.Text())
		}
	}
	if n := len(leavesOf(t, crashed, auditchain.EventEvidence)); n != 5 {
		t.Fatalf("листьев улик %d, ожидали 5 (без дублей)", n)
	}
}

// Журнал потерял улики, которые цепь уже знает: запускаться нельзя.
func TestLostEvidenceStopsStart(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	s.Close()
	evDir, _, _ := dirs(cfg)
	seg := filepath.Join(evDir, "seg_00000000000000000001.log")
	data, _ := os.ReadFile(seg)
	os.WriteFile(seg, data[:len(data)-5], 0o600) // хвост «оборван»: последней улики нет
	if _, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true}); !errors.Is(err, ErrEvidenceLost) {
		t.Fatalf("потеря подтверждённой улики: %v", err)
	}
}

// Время приёма монотонно, даже если часы прыгнули назад.
func TestReceivedAtIsMonotonic(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ingest(t, s, "abs-core", 1, 1)
	c.add(-time.Hour)
	ingest(t, s, "abs-core", 2, 2)
	var prev int64
	for q := uint64(1); q <= 2; q++ {
		b, _ := s.Proof("abs-core", q, false)
		sealed, _ := evidence.Unmarshal(b.Evidence)
		if sealed.ReceivedAt <= prev {
			t.Fatalf("время приёма пошло назад: %d после %d", sealed.ReceivedAt, prev)
		}
		prev = sealed.ReceivedAt
	}
}

// Пропуск номеров и молчание источника — события в цепи.
func TestGapsAndSilence(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	ingest(t, s, "abs-core", 5, 5)
	c.add(5 * time.Minute)
	s.CheckSilence(c.now())
	c.add(6 * time.Minute)
	s.CheckSilence(c.now())
	s.CheckSilence(c.now()) // одно событие на эпизод
	s.Close()
	gaps := leavesOf(t, cfg, auditchain.EventGap)
	if len(gaps) != 1 || gaps[0].Scope != "abs-core" || !strings.Contains(string(gaps[0].Payload), `"from":2,"to":4`) {
		t.Fatalf("пропуски: %+v", gaps)
	}
	silence := leavesOf(t, cfg, auditchain.EventSilence)
	if len(silence) != 1 || silence[0].Scope != "abs-core" {
		t.Fatalf("молчание: %+v", silence)
	}
}

// ⭐ Стирание по сроку: месяц закрывается, заявка двух людей, уничтожение.
// Тело больше не открыть, а доказательство существования и неизменности
// проходит; каждое состояние ключа — квитанция в цепи.
func TestRetentionErasure(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 2)
	scope := "abs-core/2026-09"

	c.set(time.Date(2026, 10, 1, 0, 10, 0, 0, time.UTC))
	s.Maintain(c.now())
	if ki, _ := s.keyInfo(scope); ki.State != keyring.Deactivated {
		t.Fatalf("сентябрь не закрыт: %v", ki.State)
	}
	if due := s.RetentionDue(c.now()); len(due) != 0 {
		t.Fatalf("срок ещё не вышел: %+v", due)
	}
	c.set(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	due := s.RetentionDue(c.now())
	if len(due) != 1 || due[0].Scope != scope {
		t.Fatalf("к уничтожению: %+v", due)
	}
	if _, err := s.ScheduleDestroy(scope, time.Hour, []keyring.Approval{{Who: "operator"}}); !errors.Is(err, keyring.ErrApproval) {
		t.Fatalf("одно подтверждение: %v", err)
	}
	if _, err := s.ScheduleDestroy(scope, time.Hour, []keyring.Approval{{Who: "operator"}, {Who: "security"}}); err != nil {
		t.Fatal(err)
	}
	c.add(2 * time.Hour)
	s.Maintain(c.now())
	mustStamp(t, s)

	b, err := s.Proof("abs-core", 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.DEK) != 0 {
		t.Fatal("выдан ключ записи стёртого месяца")
	}
	r := proof.Verify(b, trustOf(t, s))
	if !r.Valid() || r.BodyOpened {
		t.Fatalf("после стирания:\n%s", r.Text())
	}
	s.Close()
	var states []string
	for _, l := range leavesOf(t, cfg, auditchain.EventKeyState) {
		if l.Scope == scope {
			states = append(states, l.Subject)
		}
	}
	want := []string{"active", "deactivated", "pending-destruction", "destroyed-effective"}
	if strings.Join(states, ",") != strings.Join(want, ",") {
		t.Fatalf("квитанции ключа: %v, ожидали %v", states, want)
	}
}

// ⭐ Откат keyring.dat к старой копии виден по цепи: цепь помнит, что
// месяц закрыт, а подложенный кейринг говорит «активен».
func TestKeyringRollbackDetected(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	old, err := os.ReadFile(filepath.Join(cfg.DataDir, keyring.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Deactivate(false, "abs-core/2026-09"); !errors.Is(err, ErrCurrentMonth) {
		t.Fatalf("закрытие текущего месяца без force: %v", err)
	}
	if err := s.Deactivate(true, "abs-core/2026-09"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := os.WriteFile(filepath.Join(cfg.DataDir, keyring.FileName), old, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true}); !errors.Is(err, ErrKeyringMismatch) {
		t.Fatalf("откат кейринга: %v", err)
	}
}

// Падение между записью кейринга и квитанцией: квитанция дописывается при
// подъёме с пометкой «восстановлена».
func TestKeyEventRecoveredAfterCrash(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	s.flush()
	if err := s.keys.Deactivate("abs-core/2026-09"); err != nil { // кейринг записан, квитанции нет
		t.Fatal(err)
	}
	crashed := copyDirs(t, cfg)
	s2 := openStore(t, crashed, c)
	s2.Close()
	var got []string
	for _, l := range leavesOf(t, crashed, auditchain.EventKeyState) {
		if l.Scope == "abs-core/2026-09" {
			got = append(got, l.Subject+":"+fmt.Sprint(bytes.Contains(l.Payload, []byte(`"recovered":true`))))
		}
	}
	if strings.Join(got, ",") != "active:false,deactivated:true" {
		t.Fatalf("квитанции: %v", got)
	}
}

// Токен, которому не верит проверка, в цепь не ложится: проверяющий его
// потом не примет.
func TestStampRejectsUntrustedToken(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ingest(t, s, "abs-core", 1, 1)
	s.tsaTrust = openStore(t, testConfig(t), c).TSATrust() // чужой корень
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	before := s.Head()
	if _, err := s.Stamp(context.Background()); err == nil {
		t.Fatal("непроверенный токен принят")
	}
	if s.Head() != before {
		t.Fatal("отвергнутый токен изменил цепь")
	}
}

// ⭐ Копия наружу и восстановление: другая машина собирает журнал и цепь из
// копии, ключи — из резерва ключей; пакеты доказательств проходят. Копия с
// подменённым куском не восстанавливается.
func TestReplicaRestore(t *testing.T) {
	c := newClock()
	remoteDir, backupDir := t.TempDir(), filepath.Join(t.TempDir(), "keys-backup")
	cfg := testConfig(t, func(c *config.Config) {
		c.Replica.URL = "file://" + remoteDir
		c.Keys.BackupDir = backupDir
	})
	s := openStore(t, cfg, c)
	remote, err := ship.OpenRemote(cfg.Replica.URL)
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if n, err := s.ShipOnce(context.Background(), remote); err != nil || n == 0 {
		t.Fatalf("первая копия: %d, %v", n, err)
	}
	ingest(t, s, "abs-core", 4, 5)
	mustStamp(t, s)
	if _, err := s.ShipOnce(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ShipOnce(context.Background(), remote); err != nil || n != 0 {
		t.Fatalf("повторная копия без новых данных: %d, %v", n, err)
	}
	s.Close()

	// Новая машина: копия + keyring.dat (резерв ключей) + корни + ключ подписи.
	restored := *cfg
	restored.DataDir = filepath.Join(t.TempDir(), "data")
	restored.AdminSocket = ""
	restored.Defaults()
	pub, _ := base64.RawStdEncoding.DecodeString(s.PublicKey())
	rep, err := RestoreReplica(context.Background(), remote, restored.DataDir, ed25519.PublicKey(pub))
	if err != nil {
		t.Fatal(err)
	}
	if rep.HeadSeq == 0 || rep.Files < 3 {
		t.Fatalf("восстановлено: %+v", rep)
	}
	for _, name := range []string{keyring.FileName, "sign.key"} {
		data, err := os.ReadFile(filepath.Join(cfg.Keys.BackupDir, name))
		if err != nil {
			t.Fatalf("в резерве ключей нет %s: %v", name, err)
		}
		dst := filepath.Join(restored.DataDir, name)
		if name == "sign.key" {
			dst = filepath.Join(restored.DataDir, "chain", name)
		}
		os.WriteFile(dst, data, 0o600)
	}
	_, _, tsaDir := dirs(cfg)
	_, _, tsaDir2 := dirs(&restored)
	os.CopyFS(tsaDir2, os.DirFS(tsaDir))
	restored.Replica.URL = ""
	s2 := openStore(t, &restored, c)
	if s2.PublicKey() != s.PublicKey() {
		t.Fatal("после восстановления другой ключ подписи")
	}
	for q := uint64(1); q <= 5; q++ {
		b, err := s2.Proof("abs-core", q, true)
		if err != nil {
			t.Fatalf("seq %d: %v", q, err)
		}
		if r := proof.Verify(b, trustOf(t, s2)); !r.Valid() || string(r.Body) != fmt.Sprintf("abs-core event %d", q) {
			t.Fatalf("seq %d:\n%s", q, r.Text())
		}
	}

	// Пропавший кусок журнала улик — дыра, а не «короткий журнал».
	evKeys, _ := remote.List(context.Background(), "evidence/")
	if len(evKeys) < 2 {
		t.Fatalf("кусков журнала %d, нужно хотя бы 2", len(evKeys))
	}
	holed := filepath.Join(t.TempDir(), "holed")
	os.CopyFS(holed, os.DirFS(remoteDir))
	os.Remove(filepath.Join(holed, filepath.FromSlash(evKeys[0])))
	holedRemote, _ := ship.OpenRemote("file://" + holed)
	if _, err := RestoreReplica(context.Background(), holedRemote, filepath.Join(t.TempDir(), "data"), ed25519.PublicKey(pub)); err == nil {
		t.Fatal("копия с дырой восстановилась")
	}

	// Чужая, но внутренне правильная цепь в копии (CRC и хэши сходятся):
	// ловит только сверка с подписанной головой.
	other := testConfig(t, func(c *config.Config) { c.Replica.URL = "file://" + t.TempDir() })
	so := openStore(t, other, c)
	otherRemote, _ := ship.OpenRemote(other.Replica.URL)
	for i := uint64(1); i <= 12; i++ {
		ingest(t, so, "abs-core", i, i)
		so.flush()
	}
	if _, err := so.ShipOnce(context.Background(), otherRemote); err != nil {
		t.Fatal(err)
	}
	forged := filepath.Join(t.TempDir(), "forged")
	os.CopyFS(forged, os.DirFS(remoteDir))
	os.RemoveAll(filepath.Join(forged, "chain"))
	os.CopyFS(filepath.Join(forged, "chain"), os.DirFS(filepath.Join(strings.TrimPrefix(other.Replica.URL, "file://"), "chain")))
	forgedRemote, _ := ship.OpenRemote("file://" + forged)
	if _, err := RestoreReplica(context.Background(), forgedRemote, filepath.Join(t.TempDir(), "data"), ed25519.PublicKey(pub)); err == nil {
		t.Fatal("копия с чужой цепью восстановилась")
	}

	// Подмена куска цепи в копии ловится.
	keys, _ := remote.List(context.Background(), "chain/chain.log/")
	data, _ := remote.Get(context.Background(), keys[0])
	data[len(data)-3] ^= 1
	remote.Put(context.Background(), keys[0], data)
	if _, err := RestoreReplica(context.Background(), remote, filepath.Join(t.TempDir(), "data"), ed25519.PublicKey(pub)); err == nil {
		t.Fatal("подменённая копия восстановилась")
	}
}
