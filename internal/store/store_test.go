package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/ship"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
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
		Demo:     true,
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
	data, _ := json.Marshal(b)
	b2, err := proof.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if r2 := proof.Verify(b2, trustOf(t, s)); !r2.Valid() {
		t.Fatalf("после JSON:\n%s", r2.Text())
	}
}

// ⭐ P-06: пакет — от головы, которую заверяет T1, до головы под T2. Звенья,
// легшие после T2, проверке не нужны, и пакет по старой улике от них не
// растёт. Без T2 пакет доходит до текущей головы.
func TestProofEndsAtUpperStamp(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	link := func(seq uint64) {
		t.Helper()
		ingest(t, s, "abs-core", seq, seq)
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
	}
	for q := uint64(1); q <= 3; q++ {
		link(q) // звенья до T1: пакет начинается не с первого
	}
	mustStamp(t, s) // T1
	c.add(time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	c.add(time.Minute)
	mustStamp(t, s) // T2

	before, err := s.Proof("abs-core", 5, true)
	if err != nil {
		t.Fatal(err)
	}
	for q := uint64(7); q <= 56; q++ {
		link(q) // 50 звеньев после T2
	}
	b, err := s.Proof("abs-core", 5, true)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.Verify(b, trustOf(t, s)); !r.Valid() {
		t.Fatalf("пакет не прошёл:\n%s", r.Text())
	}
	if b.Lower == nil || b.Upper == nil {
		t.Fatalf("в пакете нет меток: lower=%v upper=%v", b.Lower != nil, b.Upper != nil)
	}
	stamped, err := strconv.ParseUint(b.Lower.Inclusion.Leaf.Subject, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	first, last := b.Links[0].Seq, b.Links[len(b.Links)-1].Seq
	if first != stamped || last != b.Upper.HeadSeq || b.Statement.HeadSeq != last {
		t.Fatalf("звенья %d…%d, T1 заверяет голову %d, T2 — %d, заявление о голове %d",
			first, last, stamped, b.Upper.HeadSeq, b.Statement.HeadSeq)
	}
	if head := s.chain.Head().Seq; len(b.Links) != len(before.Links) || head < last+50 {
		t.Fatalf("звеньев в пакете %d, до новых звеньев было %d; голова %d", len(b.Links), len(before.Links), head)
	}

	// Без T2 — до текущей головы.
	nb, err := s.Proof("abs-core", 56, false)
	if err != nil {
		t.Fatal(err)
	}
	tr := trustOf(t, s)
	tr.AllowNoTSA = true
	if r := proof.Verify(nb, tr); !r.Valid() {
		t.Fatalf("пакет без T2:\n%s", r.Text())
	}
	if end, head := nb.Links[len(nb.Links)-1].Seq, s.chain.Head().Seq; nb.Upper != nil || end != head {
		t.Fatalf("пакет без T2 кончается звеном %d, голова %d", end, head)
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
		data, _ := json.Marshal(good)
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

// Повтор безопасен: уже принятое отвечает «duplicate» с тем же обещанием,
// что при приёме (сборщик мог упасть до записи обещания), в том числе после
// рестарта; сборщик после переустановки узнаёт последний номер.
func TestDuplicatesAndLastSeq(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	first := ingest(t, s, "abs-core", 1, 3)
	res := ingest(t, s, "abs-core", 2, 4)
	if res[0].Status != StatusDuplicate || res[1].Status != StatusDuplicate || res[2].Status != StatusAccepted {
		t.Fatalf("повторы: %+v", res)
	}
	for i, r := range res[:2] {
		if r.Promise == nil || !reflect.DeepEqual(*r.Promise, *first[i+1].Promise) || r.Digest != first[i+1].Digest {
			t.Fatalf("повтор %d: обещание %+v, при приёме %+v", r.Seq, r.Promise, first[i+1].Promise)
		}
	}
	accepted4 := res[2]
	s.Close()
	s2 := openStore(t, cfg, c)
	if last, err := s2.LastSeq("abs-core"); err != nil || last != 4 {
		t.Fatalf("LastSeq: %d, %v", last, err)
	}
	res = ingest(t, s2, "abs-core", 4, 5)
	if res[0].Status != StatusDuplicate || res[1].Status != StatusAccepted {
		t.Fatalf("после рестарта: %+v", res)
	}
	if res[0].Promise == nil || !reflect.DeepEqual(*res[0].Promise, *accepted4.Promise) {
		t.Fatalf("повтор после рестарта: обещание %+v, при приёме %+v", res[0].Promise, accepted4.Promise)
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

// ⭐ Под занятым номером другое тело (сборщик откатили к старой копии или
// второй сборщик с тем же сертификатом): не «duplicate», который молча
// потерял бы запись, а отказ всей пачке и событие в цепи. Стёртое тело
// сверить нечем — тоже конфликт.
func TestSeqConflict(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 2)
	_, err := s.Ingest("abs-core", []Incoming{
		{Seq: 2, Body: []byte("written after the collector was rolled back")},
		{Seq: 3, Body: []byte("abs-core event 3")},
	})
	if !errors.Is(err, ErrSeqConflict) {
		t.Fatalf("конфликт: %v", err)
	}
	if last, _ := s.LastSeq("abs-core"); last != 2 {
		t.Fatalf("из пачки с конфликтом принято: LastSeq %d", last)
	}
	b, err := s.Proof("abs-core", 2, true)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := evidence.Unmarshal(b.Evidence)
	if body, _ := keyring.OpenWithDEK(sealed.Envelope, b.DEK); string(body) != "abs-core event 2" {
		t.Fatalf("принятое тело заменено: %q", body)
	}
	if n := s.sources["abs-core"].conflicts.Load(); n != 1 {
		t.Fatalf("конфликтов %d", n)
	}

	// Ключ месяца ждёт уничтожения: повтор того же тела сверить нечем,
	// «duplicate» сказать нельзя, и причина названа как есть, а не «стёрто».
	scope := "abs-core/2026-09"
	if err := s.Deactivate(true, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ScheduleDestroy(context.Background(), scope, time.Hour, []keyring.Approval{{Who: "operator"}, {Who: "security"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest("abs-core", []Incoming{{Seq: 1, Body: []byte("abs-core event 1")}}); !errors.Is(err, ErrSeqConflict) {
		t.Fatalf("стёртое тело: %v", err)
	}
	s.Close()
	events := leavesOf(t, cfg, auditchain.EventConflict)
	if len(events) != 2 || events[0].Scope != "abs-core" || !strings.Contains(string(events[0].Payload), `"seq":2`) ||
		!strings.Contains(string(events[1].Payload), "pending destruction") {
		t.Fatalf("события конфликта в цепи: %+v", events)
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
	if _, err := s.ScheduleDestroy(context.Background(), scope, time.Hour, []keyring.Approval{{Who: "operator"}}); !errors.Is(err, keyring.ErrApproval) {
		t.Fatalf("одно подтверждение: %v", err)
	}
	if _, err := s.ScheduleDestroy(context.Background(), scope, time.Hour, []keyring.Approval{{Who: "operator"}, {Who: "security"}}); err != nil {
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
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	s.tsaTrust = openStore(t, testConfig(t), c).TSATrust() // чужой корень
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	before := s.Head()
	if _, err := s.Stamp(context.Background()); err == nil {
		t.Fatal("непроверенный токен принят")
	}
	// До запроса в цепь легли хвосты источников (п. 28) — одни в своём
	// звене; токена нет. Повтор метки звено хвостов не множит: при лежащей
	// TSA цепь не растёт на каждую попытку.
	after := s.Head()
	if after.Seq != before.Seq+1 {
		t.Fatalf("голова %d, до метки %d: ждали одно звено хвостов", after.Seq, before.Seq)
	}
	if _, err := s.Stamp(context.Background()); err == nil {
		t.Fatal("непроверенный токен принят при повторе")
	}
	if s.Head() != after {
		t.Fatal("повтор отвергнутой метки изменил цепь")
	}
	s.Close()
	if n := len(leavesOf(t, cfg, auditchain.EventTimestamp)); n != 0 {
		t.Fatalf("в цепи %d листов метки после отвергнутого токена", n)
	}
	if tails := leavesOf(t, cfg, auditchain.EventTails); len(tails) != 1 {
		t.Fatalf("листов хвостов %d, ждали один", len(tails))
	}
}

// ⭐ Копия наружу и восстановление: другая машина собирает журнал и цепь из
// копии, ключи — из резерва ключей; пакеты доказательств проходят. Копия с
// подменённым куском не восстанавливается.
func TestReplicaRestore(t *testing.T) {
	c := newClock()
	remoteDir, backupDir := t.TempDir(), t.TempDir()
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

// keyStates — метки состояний скоупа в цепи по порядку.
func keyStates(t *testing.T, cfg *config.Config, scope string) string {
	t.Helper()
	var got []string
	for _, l := range leavesOf(t, cfg, auditchain.EventKeyState) {
		if l.Scope == scope {
			got = append(got, l.Subject)
		}
	}
	return strings.Join(got, ",")
}

// restoreFromCopy — восстановление на новой машине по README: журнал и цепь
// из копии, keyring.dat и sign.key из резерва ключей, корни на месте.
func restoreFromCopy(t *testing.T, cfg *config.Config, remote ship.Remote, pub string) *config.Config {
	t.Helper()
	restored := *cfg
	restored.DataDir = filepath.Join(t.TempDir(), "data")
	restored.AdminSocket = ""
	restored.Replica.URL = ""
	restored.Defaults()
	key, _ := base64.RawStdEncoding.DecodeString(pub)
	if _, err := RestoreReplica(context.Background(), remote, restored.DataDir, ed25519.PublicKey(key)); err != nil {
		t.Fatal(err)
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
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, _, tsaDir := dirs(cfg)
	_, _, tsaDir2 := dirs(&restored)
	if err := os.CopyFS(tsaDir2, os.DirFS(tsaDir)); err != nil {
		t.Fatal(err)
	}
	return &restored
}

// ⭐ Резерв ключей лёг в момент смены ключа, потом умер диск данных.
// Восстановление по README поднимает хранилище: в цепь ложатся только
// состояния, дошедшие до резерва, поэтому keyring.dat из резерва не бывает
// позади цепи (раньше старт отказывал с ErrKeyringMismatch).
func TestRestoreAfterFailedKeyringBackup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(s *Store) error
	}{
		{"новый месяц", func(s *Store) error {
			_, err := s.Ingest("abs-core", []Incoming{{Seq: 4, Body: []byte("x")}})
			return err
		}},
		{"закрытие месяца", func(s *Store) error { return s.Deactivate(true, "abs-core/2026-09") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newClock()
			remoteDir, backupDir := t.TempDir(), t.TempDir()
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

			if err := os.Chmod(backupDir, 0o500); err != nil {
				t.Fatal(err)
			}
			if tc.name == "новый месяц" {
				c.set(time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC))
			}
			if err := tc.change(s); !errors.Is(err, keyring.ErrBackupPending) {
				t.Fatalf("при лежащем резерве: %v", err)
			}
			if err := os.Chmod(backupDir, 0o700); err != nil {
				t.Fatal(err)
			}
			mustStamp(t, s)
			if _, err := s.ShipOnce(context.Background(), remote); err != nil {
				t.Fatal(err)
			}
			s.Close()

			restored := restoreFromCopy(t, cfg, remote, s.PublicKey())
			s2, err := Open(restored, Options{Logger: quiet, Now: c.now, NoBackground: true})
			if err != nil {
				t.Fatalf("восстановленное хранилище не стартует: %v", err)
			}
			defer s2.Close()
			for q := uint64(1); q <= 3; q++ {
				b, err := s2.Proof("abs-core", q, true)
				if err != nil || len(b.DEK) == 0 {
					t.Fatalf("улика %d после восстановления: %v", q, err)
				}
			}
		})
	}
}

// Квитанция о смене ключа ложится в цепь, когда изменение дошло до резерва:
// при лежащем резерве — позже, из обслуживания.
func TestKeyReceiptWaitsForBackup(t *testing.T) {
	c := newClock()
	backupDir := t.TempDir()
	cfg := testConfig(t, func(c *config.Config) { c.Keys.BackupDir = backupDir })
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)

	if err := os.Chmod(backupDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(backupDir, 0o700) })
	if err := s.Deactivate(true, "abs-core/2026-09"); !errors.Is(err, keyring.ErrBackupPending) {
		t.Fatalf("при лежащем резерве: %v", err)
	}
	s.Maintain(c.now())
	s.flush()
	if got := keyStates(t, cfg, "abs-core/2026-09"); got != "active" {
		t.Fatalf("квитанция до копии в резерв: %q", got)
	}
	if !s.Status().KeyringBackupPending {
		t.Fatal("статус молчит о неприехавшей копии")
	}

	if err := os.Chmod(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	s.Maintain(c.now())
	s.flush()
	if got := keyStates(t, cfg, "abs-core/2026-09"); got != "active,deactivated" {
		t.Fatalf("квитанция после копии: %q", got)
	}
	if s.Status().KeyringBackupPending {
		t.Fatal("копия прошла, а статус всё ещё ждёт")
	}
}

// keyring.dat старше улик в журнале — старт отказывает, даже если квитанция
// нового ключа не успела лечь в цепь до падения: каждый ключ, под которым
// запечатаны улики, обязан быть известен кейрингу.
func TestWrongKeyringStopsStart(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	s.flush()
	old, err := os.ReadFile(filepath.Join(cfg.DataDir, keyring.FileName))
	if err != nil {
		t.Fatal(err)
	}
	c.set(time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC))
	ingest(t, s, "abs-core", 2, 2) // новый ключ месяца; квитанция ещё в памяти
	crashed := copyDirs(t, cfg)
	if err := os.WriteFile(filepath.Join(crashed.DataDir, keyring.FileName), old, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Open(crashed, Options{Logger: quiet, Now: c.now, NoBackground: true})
	if !errors.Is(err, ErrKeyringMismatch) || !strings.Contains(err.Error(), "unknown to keyring.dat") {
		t.Fatalf("старт со старым keyring.dat: %v", err)
	}
}

// Корень, которого не знает keyring.dat, виден в статусе; оператор его
// уничтожает, и это событие ложится в цепь.
func TestOrphanRootsAdmin(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	orphan, err := rootStore(cfg).NewRoot()
	if err != nil {
		t.Fatal(err)
	}
	s := openStore(t, cfg, c)
	if got := s.Status().OrphanRoots; len(got) != 1 || got[0] != orphan {
		t.Fatalf("сирота в статусе: %v", got)
	}
	done, err := s.DestroyOrphanRoots()
	if err != nil || len(done) != 1 || done[0] != orphan {
		t.Fatalf("уничтожение сирот: %v, %v", done, err)
	}
	if got := s.Status().OrphanRoots; len(got) != 0 {
		t.Fatalf("после уничтожения: %v", got)
	}
	s.flush()
	if got := leavesOf(t, cfg, auditchain.EventRoots); len(got) != 1 || !bytes.Contains(got[0].Payload, []byte(orphan)) {
		t.Fatalf("событие в цепи: %+v", got)
	}
}

// ⭐ Окно отмены отмеряется и по метке TSA: часы хоста, ушедшие вперёд, не
// уничтожают ключ раньше срока; без метки уничтожение ждёт; метка со
// временем после срока лежит в цепи раньше квитанции об уничтожении.
func TestDestroyWaitsForTSATime(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	tsaClock := newClock() // своя служба меток — свои часы
	s.tsaLocal.Now = tsaClock.now
	ctx := context.Background()
	ingest(t, s, "abs-core", 1, 1)
	scope := "abs-core/2026-09"
	if err := s.Deactivate(true, scope); err != nil {
		t.Fatal(err)
	}
	const wait = 7 * 24 * time.Hour
	ki, err := s.ScheduleDestroy(context.Background(), scope, wait, []keyring.Approval{{Who: "operator"}, {Who: "security"}})
	if err != nil {
		t.Fatal(err)
	}
	mustStamp(t, s) // метка до срока: по ней уничтожать рано

	c.add(8 * 24 * time.Hour) // часы хоста ушли вперёд, TSA — нет
	if _, err := s.CompleteDue(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.keyInfo(scope); got.State != keyring.Pending {
		t.Fatalf("уничтожен по часам хоста: %v", got.State)
	}

	saved := s.tsaLocal
	s.tsaLocal, s.tsaURL = nil, "http://127.0.0.1:1" // служба меток недоступна
	tsaClock.add(8 * 24 * time.Hour)
	if _, err := s.CompleteDue(ctx); err == nil {
		t.Fatal("без метки уничтожение прошло молча")
	}
	if got, _ := s.keyInfo(scope); got.State != keyring.Pending {
		t.Fatalf("уничтожен без метки: %v", got.State)
	}
	s.tsaLocal, s.tsaURL = saved, ""

	changed, err := s.CompleteDue(ctx)
	if err != nil || len(changed) != 1 || changed[0].State != keyring.Destroyed {
		t.Fatalf("после срока по TSA: %+v, %v", changed, err)
	}
	s.flush()
	_, chainDir, _ := dirs(cfg)
	var lastStamp time.Time
	found := false
	if err := auditchain.ScanLeaves(chainDir, func(_ uint64, l auditchain.Leaf) error {
		switch {
		case l.Type == auditchain.EventTimestamp:
			gen, err := tsa.GenTime(l.Payload)
			if err != nil {
				return err
			}
			lastStamp = gen
		case l.Type == auditchain.EventKeyState && l.Scope == scope && strings.HasPrefix(l.Subject, "destroyed") && !found:
			found = true
			if lastStamp.Before(ki.DestroyAfter) {
				t.Errorf("перед квитанцией метка %v, срок %v", lastStamp, ki.DestroyAfter)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("квитанции уничтожения в цепи нет")
	}
}

// Только для тестов: продукт берёт голову и доверие к TSA изнутри.

// Head — голова цепи.
func (s *Store) Head() auditchain.Head {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	return s.chain.Head()
}

// TSATrust — доверие к службе меток, которым пользуется хранилище. Для
// встроенной демо-службы — её корень.
func (s *Store) TSATrust() tsa.Trust { return s.tsaTrust }
