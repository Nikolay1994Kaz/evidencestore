package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evlog"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/metrics"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/ship"
)

// Находки проверки агентами 09.10 (docs/FINDINGS.md, «Проверка агентами»):
// каждая — тест, красный на коде до исправления.

func reopen(cfg *config.Config, c *clock) (*Store, error) {
	return Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true})
}

// S-01: второй процесс над тем же data_dir не стартует — раньше он успевал
// дописать в цепь лист и звено и сдвигал первому номера листов.
func TestDataDirLocked(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	head := s.Head()
	if _, err := reopen(cfg, c); !errors.Is(err, ErrLocked) {
		t.Fatalf("второе открытие: %v", err)
	}
	if _, err := Init(cfg); !errors.Is(err, ErrLocked) {
		t.Fatalf("init при работающем хранилище: %v", err)
	}
	if got := s.Head(); got != head {
		t.Fatalf("второй процесс сдвинул цепь: %+v → %+v", head, got)
	}
	s.Close()
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatalf("после Close: %v", err)
	}
	s2.Close()
}

// G-01: файл floor в журнале улик — порча: хранилище не стартует и ничего
// не удаляет (раньше само удаляло сегменты ниже подложенной границы).
func TestFloorInEvidenceLogRefused(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	s.Close()
	evDir, _, _ := dirs(cfg)
	// «1» — граница, которую принял бы и буфер сборщика: отвергнуть её
	// можно, только если журнал улик floor не знает вовсе. «2» — не начало
	// сегмента.
	for _, floor := range []string{"1", "2"} {
		if err := os.WriteFile(filepath.Join(evDir, "floor"), []byte(floor+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if s, err := reopen(cfg, c); !errors.Is(err, evlog.ErrCorrupt) {
			if err == nil {
				s.Close()
			}
			t.Fatalf("floor %s в журнале улик: %v", floor, err)
		}
		if _, err := os.Stat(filepath.Join(evDir, fmt.Sprintf("seg_%020d.log", 1))); err != nil {
			t.Fatalf("floor %s: сегмент удалён: %v", floor, err)
		}
	}
}

// C-06, B-01: один бит в середине последнего сегмента журнала улик — отказ
// стартовать, а не срез «оборванного хвоста» вместе с подтверждёнными
// уликами за ним.
func TestBitRotInEvidenceLogRefused(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	for q := uint64(1); q <= 10; q++ {
		ingest(t, s, "abs-core", q, q)
	}
	s.Close()
	evDir, _, _ := dirs(cfg)
	path := filepath.Join(evDir, fmt.Sprintf("seg_%020d.log", 1))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/3] ^= 1
	os.WriteFile(path, data, 0o600)
	if _, err := reopen(cfg, c); !errors.Is(err, evlog.ErrCorrupt) {
		t.Fatalf("порча середины журнала улик: %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, data) {
		t.Fatalf("журнал улик обрезан: %d байт, было %d", len(after), len(data))
	}
}

// T-01, S-07: отказ записи цепи защёлкивается, и приём отказывает: раньше
// хранилище принимало улики и подписывало обещания, которые не выполнит.
func TestChainFailureStopsIntake(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	s.chain.SetBeforeWrite(func(string) error { return errors.New("EIO (тест)") })
	ingest(t, s, "abs-core", 2, 2)
	if err := s.flush(); err == nil {
		t.Fatal("отказ цепи не сработал")
	}
	s.chain.SetBeforeWrite(nil) // диск «ожил» — защёлка остаётся
	if s.Healthy() == nil {
		t.Fatal("Healthy не видит отказа цепи")
	}
	if _, err := s.Ingest("abs-core", []Incoming{{Seq: 3, Body: []byte("x")}}); err == nil {
		t.Fatal("приём идёт при отказавшей цепи")
	}
	var b strings.Builder
	metrics.Write(&b, s.Metrics(c.now()))
	if !strings.Contains(b.String(), "evidencestore_chain_failed 1\n") {
		t.Fatal("показатель evidencestore_chain_failed не поднят")
	}
}

// failingRemote роняет Put для ключей с префиксом fail.
type failingRemote struct {
	ship.Remote
	fail string
}

func (f failingRemote) Put(ctx context.Context, key string, data []byte) error {
	if strings.HasPrefix(key, f.fail) {
		return errors.New("сеть упала (тест)")
	}
	return f.Remote.Put(ctx, key, data)
}

// restoreCopy поднимает хранилище из копии в новый каталог: копия, ключи из
// резерва, демо-TSA.
func restoreCopy(t *testing.T, cfg *config.Config, s *Store, remote ship.Remote, c *clock) (*Store, error) {
	t.Helper()
	restored := *cfg
	restored.DataDir = filepath.Join(t.TempDir(), "data")
	restored.AdminSocket = ""
	restored.Replica.URL = ""
	restored.Defaults()
	pub, _ := base64.RawStdEncoding.DecodeString(s.PublicKey())
	if _, err := RestoreReplica(context.Background(), remote, restored.DataDir, ed25519.PublicKey(pub)); err != nil {
		return nil, err
	}
	for name, dst := range map[string]string{
		keyring.FileName: filepath.Join(restored.DataDir, keyring.FileName),
		"sign.key":       filepath.Join(restored.DataDir, "chain", "sign.key"),
	} {
		data, err := os.ReadFile(filepath.Join(cfg.Keys.BackupDir, name))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(dst, data, 0o600)
	}
	_, _, tsaDir := dirs(cfg)
	_, _, tsaDir2 := dirs(&restored)
	os.CopyFS(tsaDir2, os.DirFS(tsaDir))
	return reopen(&restored, c)
}

func replicaConfig(t *testing.T) (*config.Config, ship.Remote) {
	t.Helper()
	remoteDir := t.TempDir()
	cfg := testConfig(t, func(c *config.Config) {
		c.Replica.URL = "file://" + remoteDir
		c.Keys.BackupDir = t.TempDir()
	})
	remote, err := ship.OpenRemote(cfg.Replica.URL)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, remote
}

// S-03: проход копии, прерванный на журнале улик, не оставляет в копии
// цепь, которая знает улики, которых в копии нет: журнал уезжает первым.
// Раньше цепь уезжала первой, и восстановленное хранилище не стартовало
// (ErrEvidenceLost).
func TestReplicaInterruptedPassRestores(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if _, err := s.ShipOnce(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 4, 6)
	mustStamp(t, s)
	if _, err := s.ShipOnce(context.Background(), failingRemote{remote, "evidence/"}); err == nil {
		t.Fatal("отказ копии не сработал")
	}
	s.Close()
	s2, err := restoreCopy(t, cfg, s, remote, c)
	if err != nil {
		t.Fatalf("восстановление после прерванного прохода: %v", err)
	}
	defer s2.Close()
	if _, err := s2.Proof("abs-core", 3, false); err != nil {
		t.Fatalf("доехавшая улика: %v", err)
	}
}

// Z-07: проход копии прервался между звеньями и листьями цепи. В копии не
// бывает звеньев над листьями, которых в ней нет: листья уезжают раньше
// chain.log — в том же порядке, в каком цепь пишет сама. Раньше chain.log
// уезжал первым (по алфавиту), и копия, прерванная на листьях, не
// поднималась: «звено покрывает лист N, а в файлах листьев их M» (нашла
// симуляция с падениями).
func TestReplicaInterruptedBetweenLinksAndLeaves(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if _, err := s.ShipOnce(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 4, 6)
	mustStamp(t, s)
	if _, err := s.ShipOnce(context.Background(), failingRemote{remote, "chain/leaves_"}); err == nil {
		t.Fatal("отказ копии не сработал")
	}
	s.Close()
	s2, err := restoreCopy(t, cfg, s, remote, c)
	if err != nil {
		t.Fatalf("восстановление после прохода, прерванного на листьях: %v", err)
	}
	defer s2.Close()
	if _, err := s2.Proof("abs-core", 3, false); err != nil {
		t.Fatalf("доехавшая улика: %v", err)
	}
}

// Z-08: подъём из копии с прерванным проходом отрезает хвост (Z-07), а
// поднятое хранилище пишет ту же копию дальше — следующий подъём из неё
// обязан пройти. Раньше оно дописывало копию с отрезанного места: отправка
// отказывала («file was truncated»), пока файл не дорастал до мёртвого
// хвоста копии, а потом молча слала байты, которые с ним не стыкуются.
func TestRestoredStoreContinuesCopy(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	ctx := context.Background()
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 4, 6)
	mustStamp(t, s)
	if _, err := s.ShipOnce(ctx, failingRemote{remote, "chain/leaves_"}); err == nil {
		t.Fatal("отказ копии не сработал")
	}
	s.Close()
	s2, err := restoreCopy(t, cfg, s, remote, c)
	if err != nil {
		t.Fatal(err)
	}
	// Цепь поднятого дорастает за мёртвый хвост копии.
	for q := uint64(7); q <= 30; q++ {
		ingest(t, s2, "abs-core", q, q)
		mustStamp(t, s2)
	}
	if _, err := s2.ShipOnce(ctx, remote); err != nil {
		t.Fatalf("копия после подъёма: %v", err)
	}
	s2.Close()
	s3, err := restoreCopy(t, cfg, s2, remote, c)
	if err != nil {
		t.Fatalf("второй подъём из копии: %v", err)
	}
	defer s3.Close()
	for _, q := range []uint64{3, 6, 30} {
		if _, err := s3.Proof("abs-core", q, false); err != nil {
			t.Fatalf("улика %d после второго подъёма: %v", q, err)
		}
	}
}

// Z-09: data_dir потерял уже скопированное (диск соврал про fsync) и пишет
// журнал дальше. Копию с её смещений дописывать нельзя: байты не стыкуются
// с её кусками. Раньше отправка отказывала, только пока файл был короче
// скопированного, а дорастя — молча слала чужие байты, и копия переставала
// собираться.
func TestShipRefusesDataDirBehindCopy(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	ctx := context.Background()
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 4, 5) // в журнале, в цепь ещё не легли
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	lied := copyDirs(t, cfg) // диск в момент отказа питания
	s.Close()
	// Диск соврал: последней записи журнала, уже скопированной, на нём нет.
	evDir, _, _ := dirs(lied)
	segs, _ := filepath.Glob(filepath.Join(evDir, "seg_*.log"))
	offs := frameStarts(t, segs[len(segs)-1], 16, true)
	if err := os.Truncate(segs[len(segs)-1], offs[len(offs)-1]); err != nil {
		t.Fatal(err)
	}
	s2, err := reopen(lied, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	ingest(t, s2, "abs-core", 6, 40) // журнал дорастает за скопированное
	mustStamp(t, s2)
	if _, err := s2.ShipOnce(ctx, remote); !errors.Is(err, ErrReplicaDiverged) {
		t.Fatalf("отправка в копию, которую data_dir не продолжает: %v", err)
	}
	// Копия по-прежнему собирается, и в ней — то, что потерял диск.
	s3, err := restoreCopy(t, cfg, s, remote, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if _, err := s3.Proof("abs-core", 5, false); err != nil {
		t.Fatalf("улика, потерянная диском, из копии: %v", err)
	}
}

// Поколение, чей первый проход не дошёл до подписанной головы, подъём
// пропускает и собирает предыдущее; следующее поколение получает новый
// номер, а не пишет поверх недописанного.
func TestRestoreSkipsGenerationWithoutHead(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	ctx := context.Background()
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := restoreCopy(t, cfg, s, remote, c)
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, s2, "abs-core", 4, 6)
	mustStamp(t, s2)
	if _, err := s2.ShipOnce(ctx, failingRemote{remote, genPrefix(1) + "heads/"}); err == nil {
		t.Fatal("отказ копии не сработал")
	}
	s2.Close()
	s3, err := restoreCopy(t, cfg, s2, remote, c)
	if err != nil {
		t.Fatalf("подъём при поколении без головы: %v", err)
	}
	if _, err := s3.Proof("abs-core", 3, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s3.Proof("abs-core", 4, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("улика из поколения без головы: %v", err)
	}
	ingest(t, s3, "abs-core", 7, 9)
	mustStamp(t, s3)
	if _, err := s3.ShipOnce(ctx, remote); err != nil {
		t.Fatalf("копия после подъёма: %v", err)
	}
	s3.Close()
	s4, err := restoreCopy(t, cfg, s3, remote, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s4.Close()
	if _, err := s4.Proof("abs-core", 9, false); err != nil {
		t.Fatal(err)
	}
}

// stopAfter — копия, связь с которой рвётся после n кусков.
type stopAfter struct {
	ship.Remote
	n *int
}

func (r stopAfter) Put(ctx context.Context, key string, data []byte) error {
	if *r.n == 0 {
		return errors.New("сеть упала (тест)")
	}
	*r.n--
	return r.Remote.Put(ctx, key, data)
}

// Проход копии прерван между кусками одного сегмента журнала: копия кончается
// посреди записи. Поднятое хранилище отрезает оборванную запись при старте и
// пишет копию дальше новым поколением; следующий подъём из неё проходит.
func TestRestoreFromChunkCutMidRecord(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true, replicaChunk: 100})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 4, 10)
	mustStamp(t, s)
	n := 1
	if _, err := s.ShipOnce(ctx, stopAfter{remote, &n}); err == nil {
		t.Fatal("отказ копии не сработал")
	}
	s.Close()
	s2, err := restoreCopy(t, cfg, s, remote, c)
	if err != nil {
		t.Fatalf("подъём из копии, оборванной посреди записи: %v", err)
	}
	s2.replicaChunk = 100
	ingest(t, s2, "abs-core", 11, 12)
	mustStamp(t, s2)
	if _, err := s2.ShipOnce(ctx, remote); err != nil {
		t.Fatalf("копия после подъёма: %v", err)
	}
	s2.Close()
	s3, err := restoreCopy(t, cfg, s2, remote, c)
	if err != nil {
		t.Fatalf("второй подъём: %v", err)
	}
	defer s3.Close()
	for _, q := range []uint64{3, 12} {
		if _, err := s3.Proof("abs-core", q, false); err != nil {
			t.Fatalf("улика %d: %v", q, err)
		}
	}
}

// S-02: подписанная голова в копии не новее звеньев копии: она снимается под
// тем же замком цепи, что и размеры файлов. Раньше тик успевал добавить
// звено между снимками, и голова указывала на звено, которого в копии нет.
func TestReplicaHeadNotAheadOfShippedChain(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	ctx := context.Background()
	done := make(chan struct{})
	go func() { // «тик» цепи всё время, пока идёт копия
		for {
			select {
			case <-done:
				return
			default:
				s.flush()
			}
		}
	}()
	for q := uint64(1); q <= 20; q++ {
		ingest(t, s, "abs-core", q, q)
		if _, err := s.ShipOnce(ctx, remote); err != nil {
			t.Fatal(err)
		}
		files, heads, err := listReplica(ctx, remote, "")
		if err != nil {
			t.Fatal(err)
		}
		var chainLog []byte
		for _, ch := range files["chain/chain.log"] {
			b, _ := remote.Get(ctx, ch.key)
			chainLog = append(chainLog[:ch.start], b...)
		}
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "chain.log"), chainLog, 0o600)
		links, err := auditchain.ReadChain(dir)
		if err != nil {
			t.Fatal(err)
		}
		if seq, _ := headSeqOf(heads[len(heads)-1]); seq > uint64(len(links)) {
			close(done)
			t.Fatalf("проход %d: голова %d, а звеньев в копии %d", q, seq, len(links))
		}
	}
	close(done)
}

// Копия прежней версии могла держать голову новее своих звеньев (кусок цепи
// не доехал). Восстановление сверяется с последней головой, чьё звено в
// копии есть, а не отказывает и не падает.
func TestRestoreSkipsHeadAheadOfLinks(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	ctx := context.Background()
	ingest(t, s, "abs-core", 1, 2)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	_, heads, err := listReplica(ctx, remote, "")
	if err != nil || len(heads) == 0 {
		t.Fatalf("головы в копии: %v, %v", heads, err)
	}
	shipped, _ := headSeqOf(heads[len(heads)-1])
	ingest(t, s, "abs-core", 3, 3)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	// Голова нового состояния — в копию, а куски цепи и журнала — нет.
	s.chainMu.Lock()
	st := s.signer.Sign(s.chain.Head(), len(s.links), s.nowTime().Unix())
	s.chainMu.Unlock()
	if st.HeadSeq <= shipped {
		t.Fatalf("голова не сдвинулась: %d, в копии %d", st.HeadSeq, shipped)
	}
	data, _ := st.JSON()
	if err := remote.Put(ctx, fmt.Sprintf("heads/%020d.json", st.HeadSeq), data); err != nil {
		t.Fatal(err)
	}
	pub, _ := base64.RawStdEncoding.DecodeString(s.PublicKey())
	rep, err := RestoreReplica(ctx, remote, filepath.Join(t.TempDir(), "data"), ed25519.PublicKey(pub))
	if err != nil {
		t.Fatalf("голова новее звеньев копии: %v", err)
	}
	if rep.HeadSeq != shipped {
		t.Fatalf("сверено с головой %d, ожидали %d", rep.HeadSeq, shipped)
	}
}

// S-04: кусок внахлёст (копия прежней версии повторила его с откатившегося
// смещения) — не «дыра навсегда»: общая часть сверяется байт в байт.
// Разошедшиеся байты — отказ.
func TestReplicaRestoreToleratesOverlap(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	ctx := context.Background()
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	_, chainDir, _ := dirs(cfg)
	local, _ := os.ReadFile(filepath.Join(chainDir, "chain.log"))
	if err := remote.Put(ctx, chunkKey("chain/chain.log", 10, int64(len(local))), local[10:]); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := restoreCopy(t, cfg, s, remote, c)
	if err != nil {
		t.Fatalf("кусок внахлёст с теми же байтами: %v", err)
	}
	s2.Close()

	bad := bytes.Clone(local[5:])
	bad[0] ^= 1
	if err := remote.Put(ctx, chunkKey("chain/chain.log", 5, int64(len(local))), bad); err != nil {
		t.Fatal(err)
	}
	if _, err := restoreCopy(t, cfg, s, remote, c); err == nil {
		t.Fatal("кусок внахлёст с другими байтами принят")
	}
}

// S-05: пропуск номеров, найденный перед падением (событие ещё в памяти),
// после подъёма объявляется снова: раньше сигнал о потере пропадал молча.
func TestGapSurvivesCrash(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 4, 4) // пропуск 2–3: событие в памяти, звена нет
	crashed := copyDirs(t, cfg)
	s2 := openStore(t, crashed, c)
	s2.Close()
	var found bool
	for _, l := range leavesOf(t, crashed, auditchain.EventGap) {
		found = found || (l.Scope == "abs-core" && strings.Contains(string(l.Payload), `"from":2,"to":3`))
	}
	if !found {
		t.Fatal("пропуск 2–3 после падения не объявлен")
	}
}

// S-06: настенные часы прыгнули вперёд на сутки, монотонные — нет. Время
// приёма не уходит в будущее: его держит последняя метка TSA плюс ход
// монотонных часов. Раньше все следующие улики становились «из будущего», и
// проверка их отвергала.
func TestReceiveTimeHeldByTSAAnchor(t *testing.T) {
	c := newClock()
	var mono time.Duration
	cfg := testConfig(t)
	s, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true, Mono: func() time.Duration { return mono }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tsaClock := newClock()
	s.tsaLocal.Now = tsaClock.now
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // якорь: время TSA и монотонные часы

	c.add(24 * time.Hour) // скачок настенных часов
	got := time.Unix(0, ingest(t, s, "abs-core", 2, 2)[0].Promise.ReceivedAt)
	if d := got.Sub(tsaClock.now()); d > clockSlack {
		t.Fatalf("время приёма впереди TSA на %v", d)
	}
	mono += time.Hour // прошёл настоящий час
	tsaClock.add(time.Hour)
	got = time.Unix(0, ingest(t, s, "abs-core", 3, 3)[0].Promise.ReceivedAt)
	if d := got.Sub(tsaClock.now()); d > time.Second || d < -time.Second {
		t.Fatalf("через час время приёма разошлось с TSA на %v", d)
	}
	if s.clockCapped.Load() == 0 {
		t.Fatal("срез времени приёма не посчитан")
	}
}

// ⭐ W-01: часы хоста впереди TSA меньше чем на clockSlack. Время приёма
// не обгоняет оценку по якорю: иначе оно ложилось позже следующей метки
// T2 больше чем на секунду, и esverify навсегда отвергал законную улику
// («часы хранилища врут»). Тревога и счётчик — только за clockSlack.
// genTime метки округлён вниз до секунды: доля секунды у TSA в момент
// подписи — часть сценария.
func TestReceiveTimeNeverPassesNextStamp(t *testing.T) {
	cases := []struct {
		ahead, toStamp, frac time.Duration
		capped               bool
		gap, monoFast        time.Duration // от якоря до улики; насколько монотонные часы ушли вперёд TSA
	}{
		{300 * time.Millisecond, 150 * time.Millisecond, 800 * time.Millisecond, false, time.Minute, 0},
		{50 * time.Millisecond, 20 * time.Millisecond, 960 * time.Millisecond, false, time.Minute, 0},
		{5 * time.Second, 2 * time.Second, 100 * time.Millisecond, false, time.Minute, 0},
		{30 * time.Second, 2 * time.Second, 500 * time.Millisecond, true, time.Minute, 0},
		// Часы хоста позади на 3 минуты: время приёма поднято до окна.
		{-3 * time.Minute, 2 * time.Second, 500 * time.Millisecond, true, time.Minute, 0},
		// TSA недоступна 10 часов, монотонные часы спешат на 50 ppm, часы
		// хоста впереди на 5 с: время приёма срезается по оценке, и без
		// вычета ухода хода оценка обгоняла бы T2 на 1,8 с.
		{5 * time.Second, 150 * time.Millisecond, 0, false, 10 * time.Hour, 1800 * time.Millisecond},
	}
	for _, tc := range cases {
		tsaClock := newClock()
		tsaClock.add(tc.frac)
		host := newClock()
		host.set(tsaClock.now().Add(tc.ahead))
		var mono time.Duration
		s, err := Open(testConfig(t), Options{Logger: quiet, Now: host.now, NoBackground: true, Mono: func() time.Duration { return mono }})
		if err != nil {
			t.Fatal(err)
		}
		s.tsaLocal.Now = tsaClock.now
		ingest(t, s, "abs-core", 1, 1)
		mustStamp(t, s) // якорь
		step := func(d time.Duration) { mono += d; host.add(d); tsaClock.add(d) }
		step(tc.gap)
		mono += tc.monoFast
		ingest(t, s, "abs-core", 2, 2)
		step(tc.toStamp)
		mustStamp(t, s) // T2 улики 2
		b, err := s.Proof("abs-core", 2, false)
		if err != nil {
			t.Fatal(err)
		}
		if r := proof.Verify(b, trustOf(t, s)); !r.Valid() {
			t.Errorf("часы впереди на %v, метка через %v: законная улика не прошла проверку:\n%s", tc.ahead, tc.toStamp, r.Text())
		}
		if got := s.clockCapped.Load() > 0; got != tc.capped {
			t.Errorf("часы впереди на %v: тревога %v, ожидали %v", tc.ahead, got, tc.capped)
		}
		s.Close()
	}
}

// W-05: ответ TSA шёл 15 с. Якорь ставится по времени ответа (так оценка
// не обгоняет время TSA), и оценка отстаёт от верных часов на задержку
// ответа. Тревога «часы хоста впереди TSA» это учитывает: верные часы
// хоста не тревога. Раньше — тревога и счётчик: README велит идти
// разбираться с часами, а они в порядке.
func TestSlowTSAAnswerIsNotClockAlarm(t *testing.T) {
	host, tsaClock := newClock(), newClock()
	var mono time.Duration
	s, err := Open(testConfig(t), Options{Logger: quiet, Now: host.now, NoBackground: true, Mono: func() time.Duration { return mono }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.tsaLocal.Now = func() time.Time {
		gen := tsaClock.now()
		const lag = 15 * time.Second // ответ идёт после подписи
		mono += lag
		host.add(lag)
		tsaClock.add(lag)
		return gen
	}
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // якорь
	ingest(t, s, "abs-core", 2, 2)
	if n := s.clockCapped.Load(); n != 0 {
		t.Fatalf("верные часы хоста сочтены убежавшими вперёд: тревог %d", n)
	}
	// Часы хоста и правда убежали — тревога остаётся.
	host.add(time.Minute)
	ingest(t, s, "abs-core", 3, 3)
	if s.clockCapped.Load() == 0 {
		t.Fatal("часы хоста впереди TSA на минуту, а тревоги нет")
	}
}

// ⭐ W-13: до первой метки процесса якоря нет, и время приёма не с чем
// сверить. Часы хоста убежали на сутки, TSA ещё не ответила: одна принятая
// запись получила бы время «из будущего», а монотонность — и все следующие
// на всю длину скачка; все они навсегда не проходили бы esverify. С TSA
// хранилище не принимает до первой метки (сборщик держит строки в буфере и
// повторит), после неё время приёма — по якорю, и улика проверяется.
func TestIntakeWaitsForFirstStamp(t *testing.T) {
	tsaClock := newClock()
	host := newClock()
	host.set(tsaClock.now().Add(24 * time.Hour)) // часы хоста убежали
	s, err := Open(testConfig(t), Options{Logger: quiet, Now: host.now, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.tsaLocal.Now = tsaClock.now
	s.needAnchor = true // так в serve с настроенной TSA (фоновые циклы здесь выключены)
	if _, err := s.Ingest("abs-core", []Incoming{{Seq: 1, Body: []byte("x")}}); !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("приём до первой метки: %v", err)
	}
	mustStamp(t, s)
	ingest(t, s, "abs-core", 1, 1)
	tsaClock.add(time.Second)
	host.add(time.Second)
	mustStamp(t, s) // T2
	b, err := s.Proof("abs-core", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.Verify(b, trustOf(t, s)); !r.Valid() {
		t.Fatalf("улика после скачка часов не проходит:\n%s", r.Text())
	}
}

// W-13: в боевом режиме (фоновые циклы) с TSA приём ждёт первой метки и
// открывается сам: первая метка ставится сразу после старта.
func TestServeOpensIntakeAfterFirstStamp(t *testing.T) {
	s, err := Open(testConfig(t), Options{Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.needAnchor {
		t.Fatal("с TSA приём не ждёт первой метки")
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := s.Ingest("abs-core", []Incoming{{Seq: 1, Body: []byte("x")}})
		if err == nil {
			return
		}
		if !errors.Is(err, ErrNoAnchor) || time.Now().After(deadline) {
			t.Fatalf("приём после старта: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// W-13: TSA при старте не ответила — первая метка повторяется каждые
// anchorRetry, и приём открывается сам, как только TSA ответит, а не через
// tsa.every (10 минут). Отказ TSA здесь — метка с временем после конца
// срока её сертификата: такой токен хранилище не принимает.
func TestFirstStampRetriedUntilAnchored(t *testing.T) {
	saved := anchorRetry
	anchorRetry = 20 * time.Millisecond
	defer func() { anchorRetry = saved }()
	s, err := Open(testConfig(t), Options{Logger: quiet, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var up atomic.Bool
	s.tsaLocal.Now = func() time.Time {
		if !up.Load() {
			return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		return time.Now()
	}
	s.needAnchor = true
	if _, err := s.Stamp(context.Background()); err == nil {
		t.Fatal("ПАРНЫЙ КОНТРОЛЬ: метка недоступной TSA принята")
	}
	s.wg.Add(1)
	go s.keepAnchor()
	time.Sleep(100 * time.Millisecond)
	if err := s.anchored(); !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("приём открыт без метки: %v", err)
	}
	up.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for s.anchored() != nil {
		if time.Now().After(deadline) {
			t.Fatal("TSA ответила, а приём так и ждёт первой метки")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Q-43: TSA лежит — повторы метки реже с каждым отказом подряд (каждая
// попытка с новыми листьями кладёт звено хвостов), а приём после её
// возвращения открывается сам.
func TestAnchorRetryBacksOff(t *testing.T) {
	saved := anchorRetry
	anchorRetry = 5 * time.Millisecond
	defer func() { anchorRetry = saved }()
	s, err := Open(testConfig(t), Options{Logger: quiet, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var up atomic.Bool
	var asked atomic.Int64
	s.tsaLocal.Now = func() time.Time {
		if !up.Load() {
			asked.Add(1)
			return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		return time.Now()
	}
	s.needAnchor = true
	s.wg.Add(1)
	go s.keepAnchor()
	time.Sleep(80 * anchorRetry)
	if n := asked.Load(); n < 3 || n > 20 {
		t.Fatalf("за 80 проверок %d попыток метки, ждали от 3 до 20", n)
	}
	up.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for s.anchored() != nil {
		if time.Now().After(deadline) {
			t.Fatal("TSA ответила, а приём так и ждёт метки")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ⭐ X-01, Y-01: запись пришла в окно между токеном новой метки в цепи и
// новым якорем после долгого перерыва без метки: время приёма — по
// прежнему якорю, а T1 — новая метка. Раньше время приёма ложилось раньше
// T1 больше чем на минуту (вычет ухода хода рос с возрастом якоря), и
// законная улика навсегда не проходила esverify. Теперь якорь, по которому
// окно шире recvWindow, приём закрывает: запись в окне либо принята и
// проходит проверку (перерыв сутки), либо отвергнута до свежей метки
// (неделя, месяц) и принята после неё. Все часы верные.
func TestRecordAcceptedWhileAnchorMoves(t *testing.T) {
	for _, gap := range []time.Duration{24 * time.Hour, 8 * 24 * time.Hour, 30 * 24 * time.Hour} {
		clk := newClock()
		var mono time.Duration
		var armed, fired bool
		var inWindow error
		var s *Store
		s, err := Open(testConfig(t), Options{Logger: quiet, Now: clk.now, NoBackground: true, Mono: func() time.Duration {
			if armed && !fired {
				// Токен уже в цепи, якорь ещё прежний: запись 2.
				fired = true
				_, inWindow = s.Ingest("abs-core", []Incoming{{Seq: 2, Body: []byte("abs-core event 2")}})
			}
			return mono
		}})
		if err != nil {
			t.Fatal(err)
		}
		s.needAnchor = true // так в serve с TSA
		s.tsaLocal.Now = func() time.Time {
			if !fired && !armed && mono > 0 {
				armed = true // идёт метка после перерыва
			}
			return clk.now()
		}
		if _, err := s.stampNow(context.Background()); err != nil { // якорь
			t.Fatal(err)
		}
		ingest(t, s, "abs-core", 1, 1)
		mono += gap
		clk.add(gap)
		if _, err := s.stampNow(context.Background()); err != nil { // новая метка; в окне — запись 2
			t.Fatal(err)
		}
		armed = false
		switch {
		case !fired:
			t.Fatal("запись в окне не пришла: сценарий не воспроизведён")
		case gap > 2*24*time.Hour && !errors.Is(inWindow, ErrNoAnchor):
			t.Fatalf("перерыв %v: якорь несвеж, а запись в окне не отвергнута: %v", gap, inWindow)
		case errors.Is(inWindow, ErrNoAnchor):
			ingest(t, s, "abs-core", 2, 2) // сборщик повторил после свежей метки
		case inWindow != nil:
			t.Fatal(inWindow)
		}
		ingest(t, s, "abs-core", 3, 3)
		clk.add(time.Second)
		mono += time.Second
		mustStamp(t, s) // T2
		for q := uint64(1); q <= 3; q++ {
			b, err := s.Proof("abs-core", q, false)
			if err != nil {
				t.Fatal(err)
			}
			if r := proof.Verify(b, trustOf(t, s)); !r.Valid() {
				t.Errorf("перерыв %v: законная улика %d не прошла:\n%s", gap, q, r.Text())
			}
		}
		s.Close()
	}
}

// Y-01: в простой (в цепь ничего не ложится) якорь не стареет: старше
// anchorRefresh — несвеж, и keepAnchor ставит метку, хотя заверять нечего.
// Раньше метка ставилась только при новых листьях, и якорь старел без
// предела.
func TestAnchorRefreshedWhenIdle(t *testing.T) {
	saved := anchorRetry
	anchorRetry = 10 * time.Millisecond
	defer func() { anchorRetry = saved }()
	var mono atomic.Int64
	s, err := Open(testConfig(t), Options{Logger: quiet, NoBackground: true, Mono: func() time.Duration { return time.Duration(mono.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.needAnchor = true
	if _, err := s.stampNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.anchorStale() {
		t.Fatal("ПАРНЫЙ КОНТРОЛЬ: свежий якорь сочтён несвежим")
	}
	mono.Add(int64(anchorRefresh + time.Minute)) // простой дольше anchorRefresh
	if !s.anchorStale() {
		t.Fatal("якорю больше anchorRefresh, а он свеж")
	}
	s.mu.Lock()
	before := s.anchorMono
	s.mu.Unlock()
	s.wg.Add(1)
	go s.keepAnchor()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		moved := s.anchorMono != before
		s.mu.Unlock()
		if moved {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("в простой якорь не освежён")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// S-08: цепь есть, а sign.key нет — отказ стартовать (новый ключ молча
// сменил бы подпись). Ключ подписи уходит в резерв и тогда, когда резерв
// включили после init.
func TestSigningKeyGuarded(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	pub := s.PublicKey()
	s.Close()
	_, chainDir, _ := dirs(cfg)
	key, err := os.ReadFile(filepath.Join(chainDir, "sign.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(chainDir, "sign.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := reopen(cfg, c); err == nil || !strings.Contains(err.Error(), "while the chain holds") {
		t.Fatalf("старт без ключа подписи при непустой цепи, без резерва: %v", err)
	}
	os.WriteFile(filepath.Join(chainDir, "sign.key"), key, 0o600)

	cfg.Keys.BackupDir = t.TempDir() // резерв включили позже
	s2 := openStore(t, cfg, c)
	s2.Close()
	backup, err := os.ReadFile(filepath.Join(cfg.Keys.BackupDir, "sign.key"))
	if err != nil {
		t.Fatalf("ключ подписи не попал в резерв: %v", err)
	}
	if err := os.Remove(filepath.Join(chainDir, "sign.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := reopen(cfg, c); err == nil || !strings.Contains(err.Error(), "sign.key") {
		t.Fatalf("старт без ключа подписи при непустой цепи: %v", err)
	}
	os.WriteFile(filepath.Join(chainDir, "sign.key"), backup, 0o600)
	s3 := openStore(t, cfg, c)
	if s3.PublicKey() != pub {
		t.Fatal("ключ из резерва другой")
	}
}

// P-13: data_dir потерян, keyring.dat и sign.key положены из резерва в
// корень data_dir. Цепь пуста, в data_dir/chain/ ключа нет — отказ
// стартовать: резерв не смонтирован — его не проверить, смонтирован —
// подсказка, куда положить ключ. Раньше хранилище заводило новый ключ и
// только предупреждало.
func TestSigningKeyPutBackWrong(t *testing.T) {
	c := newClock()
	cfg := testConfig(t, func(c *config.Config) { c.Keys.BackupDir = t.TempDir() })
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	pub := s.PublicKey()
	s.Close()

	lost := *cfg
	lost.DataDir = filepath.Join(t.TempDir(), "data") // data_dir потерян
	lost.AdminSocket = ""
	lost.Defaults()
	if err := os.Mkdir(lost.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{keyring.FileName, auditchain.SignKeyFileName} {
		data, err := os.ReadFile(filepath.Join(cfg.Keys.BackupDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(lost.DataDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, chainDir, newTSA := dirs(&lost)
	_, _, oldTSA := dirs(cfg)
	if err := os.CopyFS(newTSA, os.DirFS(oldTSA)); err != nil { // демо-TSA живёт в data_dir
		t.Fatal(err)
	}
	unmounted := cfg.Keys.BackupDir + "-unmounted"
	if err := os.Rename(cfg.Keys.BackupDir, unmounted); err != nil {
		t.Fatal(err)
	}
	if _, err := reopen(&lost, c); err == nil || !strings.Contains(err.Error(), "cannot be checked") {
		t.Fatalf("без sign.key, резерв не смонтирован: %v", err)
	}
	if err := os.Rename(unmounted, cfg.Keys.BackupDir); err != nil {
		t.Fatal(err)
	}
	os.Chmod(cfg.Keys.BackupDir, 0o600) // каталог есть, а заглянуть в него нельзя
	t.Cleanup(func() { os.Chmod(cfg.Keys.BackupDir, 0o700) })
	if _, err := reopen(&lost, c); err == nil || !strings.Contains(err.Error(), "cannot be checked") {
		t.Fatalf("без sign.key, резерв не прочесть: %v", err)
	}
	os.Chmod(cfg.Keys.BackupDir, 0o700)
	if _, err := reopen(&lost, c); err == nil || !strings.Contains(err.Error(), "holds the signing key") {
		t.Fatalf("без sign.key, ключ в резерве: %v", err)
	}
	if _, err := os.Stat(filepath.Join(chainDir, auditchain.SignKeyFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("заведён новый ключ подписи")
	}
	if err := os.Rename(filepath.Join(lost.DataDir, auditchain.SignKeyFileName), filepath.Join(chainDir, auditchain.SignKeyFileName)); err != nil {
		t.Fatal(err)
	}
	if s2 := openStore(t, &lost, c); s2.PublicKey() != pub {
		t.Fatal("ключ подписи сменился")
	}
}

// P-13: в резерве другой ключ подписи. При пустой цепи — отказ: хранилище
// этим ключом ещё ничего не подписало, и какой из двух верный, решает
// человек. С цепью хранилище стартует, резерв не затирает, а расхождение
// видно в статусе и метрике, пока резерв не поправят.
func TestSigningKeyDiffersFromBackup(t *testing.T) {
	c := newClock()
	cfg := testConfig(t, func(c *config.Config) { c.Keys.BackupDir = t.TempDir() })
	backup := filepath.Join(cfg.Keys.BackupDir, auditchain.SignKeyFileName)
	own, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	otherDir := t.TempDir()
	if _, err := auditchain.LoadOrCreateSigner(otherDir); err != nil {
		t.Fatal(err)
	}
	other, err := os.ReadFile(filepath.Join(otherDir, auditchain.SignKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	put := func(key []byte) {
		t.Helper()
		if err := os.WriteFile(backup, key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put(other)
	if _, err := reopen(cfg, c); !errors.Is(err, errSignerDiffers) {
		t.Fatalf("пустая цепь, в резерве другой ключ: %v", err)
	}

	put(own)
	s := openStore(t, cfg, c) // цепь больше не пуста
	ingest(t, s, "abs-core", 1, 1)
	s.Close()
	put(other)
	s2 := openStore(t, cfg, c)
	if !s2.Status().SignKeyBackupPending {
		t.Fatal("расхождение с резервом не видно в статусе")
	}
	var b strings.Builder
	if err := metrics.Write(&b, s2.Metrics(c.now())); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "evidencestore_sign_key_backup_pending 1\n") {
		t.Fatal("расхождение с резервом не видно в метрике")
	}
	if got, _ := os.ReadFile(backup); !bytes.Equal(got, other) {
		t.Fatal("ключ в резерве затёрт")
	}
	put(own)
	s2.Maintain(c.now())
	if s2.Status().SignKeyBackupPending {
		t.Fatal("тревога не снялась, когда резерв поправили")
	}
	s2.Close()

	// Ключ в резерве не прочесть (чужие права) — он тоже не затирается.
	put(other)
	os.Chmod(backup, 0)
	t.Cleanup(func() { os.Chmod(backup, 0o600) })
	s3 := openStore(t, cfg, c)
	if !s3.Status().SignKeyBackupPending {
		t.Fatal("нечитаемый ключ в резерве не виден в статусе")
	}
	os.Chmod(backup, 0o600)
	if got, _ := os.ReadFile(backup); !bytes.Equal(got, other) {
		t.Fatal("нечитаемый ключ в резерве затёрт")
	}
}

// P-12: init не заводит каталоги резерва ключей и зеркала корней — их
// заводит оператор на смонтированном диске. Пропавший каталог — отказ до
// того, как init что-то запишет. Раньше init создавал оба, и не
// смонтированный диск оставался незамеченным.
func TestInitNeedsBackupDirs(t *testing.T) {
	for _, tc := range []struct {
		name string
		file bool // на месте каталога — файл
	}{{"keys.backup_dir", false}, {"keys.roots_mirror_dir", false}, {"keys.backup_dir", true}} {
		t.Run(fmt.Sprintf("%s/file=%v", tc.name, tc.file), func(t *testing.T) {
			base := t.TempDir()
			bad := filepath.Join(base, "unmounted")
			if tc.file {
				if err := os.WriteFile(bad, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := &config.Config{
				DataDir: filepath.Join(base, "data"), RootsDir: filepath.Join(base, "roots"),
				Keys: config.Keys{BackupDir: t.TempDir(), RootsMirrorDir: t.TempDir()},
			}
			if tc.name == "keys.backup_dir" {
				cfg.Keys.BackupDir = bad
			} else {
				cfg.Keys.RootsMirrorDir = bad
			}
			cfg.Defaults()
			if _, err := Init(cfg); err == nil || !strings.Contains(err.Error(), tc.name) {
				t.Fatalf("init без %s: %v", tc.name, err)
			}
			if fi, err := os.Stat(bad); tc.file != (err == nil) || err == nil && fi.IsDir() {
				t.Fatalf("init создал %s", tc.name)
			}
			if _, err := os.Stat(filepath.Join(cfg.DataDir, keyring.FileName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("init записал keyring.dat")
			}
		})
	}
}

// P-12: каталог резерва ключей пропал (диск не смонтирован) — хранилище его
// не создаёт: копии keyring.dat и sign.key не ложатся на системный диск, а
// тревоги видны, пока диск не вернётся. Раньше каталог создавался при
// каждой копии.
func TestBackupDirNotCreated(t *testing.T) {
	c := newClock()
	backup := t.TempDir()
	cfg := testConfig(t, func(c *config.Config) { c.Keys.BackupDir = backup })
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	s.Close()
	if err := os.RemoveAll(backup); err != nil { // диск не смонтирован
		t.Fatal(err)
	}
	s2 := openStore(t, cfg, c)
	if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("каталог резерва создан сам")
	}
	if st := s2.Status(); !st.KeyringBackupPending || !st.SignKeyBackupPending {
		t.Fatalf("пропавший резерв не виден: keyring.dat %v, sign.key %v", st.KeyringBackupPending, st.SignKeyBackupPending)
	}
	if err := os.Mkdir(backup, 0o700); err != nil { // диск вернулся
		t.Fatal(err)
	}
	s2.Maintain(c.now())
	if st := s2.Status(); st.KeyringBackupPending || st.SignKeyBackupPending {
		t.Fatalf("тревоги не снялись, когда резерв вернулся: keyring.dat %v, sign.key %v", st.KeyringBackupPending, st.SignKeyBackupPending)
	}
	for _, name := range []string{keyring.FileName, auditchain.SignKeyFileName} {
		if _, err := os.Stat(filepath.Join(backup, name)); err != nil {
			t.Fatalf("%s не в резерве: %v", name, err)
		}
	}
}

// P-14: каталогов копии наружу и свидетеля (file://) нет — диск не
// смонтирован. Хранилище стартует, но проход копии и отправка голов
// отказывают, и на локальный диск ничего не ложится; каталог появился —
// проход идёт. Раньше оба каталога создавались при открытии.
func TestFileRemoteDirsNotCreated(t *testing.T) {
	c := newClock()
	ctx := context.Background()
	base := t.TempDir()
	copyDir, witnessDir := filepath.Join(base, "copy"), filepath.Join(base, "witness")
	cfg := testConfig(t, withWitness(witnessDir), func(c *config.Config) { c.Replica.URL = "file://" + copyDir })
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if _, err := s.ShipOnce(ctx, s.replicaRemote); err == nil || s.replicaErrors.Load() == 0 {
		t.Fatalf("проход копии без каталога: %v", err)
	}
	for _, d := range []string{copyDir, witnessDir} {
		if _, err := os.Stat(d); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s создан сам", d)
		}
	}
	if err := os.Mkdir(copyDir, 0o700); err != nil { // диск копии смонтирован
		t.Fatal(err)
	}
	if _, err := s.ShipOnce(ctx, s.replicaRemote); err != nil {
		t.Fatalf("проход копии с каталогом: %v", err)
	}
	if err := s.WitnessOnce(ctx); err == nil || s.witnessErrors.Load() == 0 {
		t.Fatalf("отправка голов без каталога свидетеля: %v", err)
	}
	if _, err := os.Stat(witnessDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("каталог свидетеля создан сам")
	}
	if err := os.Mkdir(witnessDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.WitnessOnce(ctx); err != nil {
		t.Fatalf("отправка голов с каталогом: %v", err)
	}
	if len(witnessHeads(t, witnessDir).Heads) == 0 {
		t.Fatal("головы не дошли до свидетеля")
	}
}

func sourceStatus(t *testing.T, s *Store, name string) SourceStatus {
	t.Helper()
	for _, src := range s.Status().Sources {
		if src.Name == name {
			return src
		}
	}
	t.Fatalf("источника %s нет в статусе", name)
	return SourceStatus{}
}

// contactEvents — события связи со сборщиком источника в цепи: вид, с какого
// контакта, до какого.
func contactEvents(t *testing.T, cfg *config.Config, source string) []string {
	t.Helper()
	var out []string
	for _, l := range leavesOf(t, cfg, auditchain.EventContact) {
		if l.Scope != source {
			continue
		}
		var ev struct {
			Since time.Time `json:"since"`
			Back  time.Time `json:"back"`
		}
		if err := json.Unmarshal(l.Payload, &ev); err != nil {
			t.Fatal(err)
		}
		e := l.Subject + " " + ev.Since.Format(time.TimeOnly)
		if !ev.Back.IsZero() {
			e += "–" + ev.Back.Format(time.TimeOnly)
		}
		out = append(out, e)
	}
	return out
}

// P-05: сборщик не выходит на связь дольше expect_contact — в цепи
// «сборщик пропал» с последним контактом, статус и тревога; вернулся — в
// цепи окно без связи. Событие одно на эпизод. Раньше пропажа сборщика была
// видна только как молчание журнала, и то через expect_every.
func TestCollectorLostAndBack(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	if err := s.Admit("abs-core", ""); err != nil {
		t.Fatal(err)
	}
	t0 := c.now()
	c.add(2 * time.Minute)
	s.CheckContact(c.now())
	if sourceStatus(t, s, "abs-core").ContactLost {
		t.Fatal("две минуты без связи — уже «пропал»")
	}
	c.add(time.Second)
	s.CheckContact(c.now())
	c.add(time.Minute)
	s.CheckContact(c.now())
	if st := sourceStatus(t, s, "abs-core"); !st.ContactLost || !st.LastContact.Equal(t0) {
		t.Fatalf("пропавший сборщик не виден: %+v", st)
	}
	var b strings.Builder
	if err := metrics.Write(&b, s.Metrics(c.now())); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `evidencestore_source_contact_lost{source="abs-core"} 1`+"\n") {
		t.Fatal("пропавший сборщик не виден в метрике")
	}
	if err := s.Admit("abs-core", ""); err != nil {
		t.Fatal(err)
	}
	t1 := c.now()
	c.add(5 * time.Second) // окно без связи кончается первым контактом, а не последним до проверки
	if err := s.Admit("abs-core", ""); err != nil {
		t.Fatal(err)
	}
	s.CheckContact(c.now())
	if sourceStatus(t, s, "abs-core").ContactLost {
		t.Fatal("вернувшийся сборщик всё ещё «пропал»")
	}
	s.Close()
	want := []string{"lost " + t0.Format(time.TimeOnly), "back " + t0.Format(time.TimeOnly) + "–" + t1.Format(time.TimeOnly)}
	if got := contactEvents(t, cfg, "abs-core"); !slices.Equal(got, want) {
		t.Fatalf("события связи %q, ожидали %q", got, want)
	}
}

// P-05: журнал молчит, а сборщик на связи (пульс без записей) — это не
// пропажа: «сборщик пропал» нет, а молчание журнала — своим чередом
// (expect_every). Так тихий журнал и остановленный сборщик различаются.
func TestQuietLogIsNotLostCollector(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ingest(t, s, "abs-core", 1, 1)
	for range 24 { // 12 минут, пульс раз в 30 с
		c.add(30 * time.Second)
		if err := s.Admit("abs-core", ""); err != nil {
			t.Fatal(err)
		}
		s.CheckContact(c.now())
		s.CheckSilence(c.now())
	}
	if st := sourceStatus(t, s, "abs-core"); st.ContactLost || !st.Silent {
		t.Fatalf("тихий журнал при живом сборщике: пропал %v, молчит %v", st.ContactLost, st.Silent)
	}
}

// P-05: обращения установки, которой хранилище отказало (чужая эпоха), — не
// контакт: подменённый сборщик не прикрывает пропажу настоящего.
func TestRefusedCollectorIsNoContact(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	if err := s.Admit("abs-core", epochA); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		c.add(30 * time.Second)
		if err := s.Admit("abs-core", epochB); !errors.Is(err, ErrEpochMismatch) {
			t.Fatalf("чужая установка: %v", err)
		}
		s.CheckContact(c.now())
	}
	if !sourceStatus(t, s, "abs-core").ContactLost {
		t.Fatal("отказанная установка продлила связь")
	}
}

// P-05: простой самого хранилища — не пропажа сборщика: отсчёт — с его
// старта. Эпизод «пропал» переживает рестарт: второго события нет, а
// «вернулся» после рестарта называет контакт до пропажи.
func TestCollectorContactAcrossRestart(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	if err := s.Admit("abs-core", ""); err != nil {
		t.Fatal(err)
	}
	s.Close()
	c.add(10 * time.Minute) // хранилище лежало
	s2 := openStore(t, cfg, c)
	c.add(time.Minute)
	s2.CheckContact(c.now())
	if sourceStatus(t, s2, "abs-core").ContactLost {
		t.Fatal("простой хранилища засчитан пропажей сборщика")
	}
	if err := s2.Admit("abs-core", ""); err != nil {
		t.Fatal(err)
	}
	t0 := c.now()
	c.add(3 * time.Minute)
	s2.CheckContact(c.now()) // пропал
	s2.Close()
	s3 := openStore(t, cfg, c)
	c.add(3 * time.Minute)
	s3.CheckContact(c.now())
	if !sourceStatus(t, s3, "abs-core").ContactLost {
		t.Fatal("эпизод «пропал» потерян при рестарте")
	}
	if err := s3.Admit("abs-core", ""); err != nil {
		t.Fatal(err)
	}
	t1 := c.now()
	s3.CheckContact(c.now())
	s3.Close()
	if sourceStatus(t, openStore(t, cfg, c), "abs-core").ContactLost { // «вернулся» в цепи закрыл эпизод
		t.Fatal("после «вернулся» и рестарта сборщик снова «пропал»")
	}
	want := []string{"lost " + t0.Format(time.TimeOnly), "back " + t0.Format(time.TimeOnly) + "–" + t1.Format(time.TimeOnly)}
	if got := contactEvents(t, cfg, "abs-core"); !slices.Equal(got, want) {
		t.Fatalf("события связи %q, ожидали %q", got, want)
	}
}

// K-02: init при ключах в резерве — отказ: так выглядит хранилище, потерявшее
// data_dir, а новый пустой кейринг затёр бы в резерве ключи всех месяцев.
func TestInitRefusesWithKeysInBackup(t *testing.T) {
	backupDir := t.TempDir()
	cfg := testConfig(t, func(c *config.Config) { c.Keys.BackupDir = backupDir })
	before, err := os.ReadFile(filepath.Join(backupDir, keyring.FileName))
	if err != nil {
		t.Fatal(err)
	}
	lost := *cfg
	lost.DataDir = filepath.Join(t.TempDir(), "data") // data_dir потерян
	lost.AdminSocket = ""
	lost.Defaults()
	if _, err := Init(&lost); !errors.Is(err, ErrBackupExists) {
		t.Fatalf("init поверх резерва: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(backupDir, keyring.FileName)); !bytes.Equal(after, before) {
		t.Fatal("резерв ключей затёрт")
	}
}

// K-03: keyring.dat, откатившийся вместе с диском, не затирает свежий
// резерв: копия в резерв — только после сверки с цепью, а младшее поколение
// поверх старшего не ложится.
func TestOldKeyringDoesNotOverwriteBackup(t *testing.T) {
	c := newClock()
	backupDir := t.TempDir()
	cfg := testConfig(t, func(c *config.Config) { c.Keys.BackupDir = backupDir })
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	old, _ := os.ReadFile(filepath.Join(cfg.DataDir, keyring.FileName))
	if err := s.Deactivate(true, "abs-core/2026-09"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	fresh, _ := os.ReadFile(filepath.Join(backupDir, keyring.FileName))
	os.WriteFile(filepath.Join(cfg.DataDir, keyring.FileName), old, 0o600)
	if err := backupFile(filepath.Join(cfg.DataDir, keyring.FileName), backupDir, 1); err == nil {
		t.Fatal("младшее поколение легло в резерв поверх старшего")
	}
	// Резерв прежней версии — без файла поколения: от отката его бережёт
	// только порядок «сверка, потом копия».
	os.Remove(filepath.Join(backupDir, keyring.FileName+".gen"))
	if _, err := reopen(cfg, c); !errors.Is(err, ErrKeyringMismatch) {
		t.Fatalf("откат кейринга: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(backupDir, keyring.FileName)); !bytes.Equal(after, fresh) {
		t.Fatal("старый keyring.dat затёр свежий резерв")
	}
}

// S-12: метка ставится, только если после прошлой в цепь легло что-то,
// кроме неё самой (иначе — каждые tsa.every вечно).
func TestStampOnlyAfterNewLeaves(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ctx := context.Background()
	ingest(t, s, "abs-core", 1, 1)
	if h, err := s.Stamp(ctx); err != nil || h == 0 {
		t.Fatalf("первая метка: %d, %v", h, err)
	}
	if h, err := s.Stamp(ctx); err != nil || h != 0 {
		t.Fatalf("метка без новых листьев: %d, %v", h, err)
	}
	ingest(t, s, "abs-core", 2, 2)
	if h, err := s.Stamp(ctx); err != nil || h == 0 {
		t.Fatalf("метка после улики: %d, %v", h, err)
	}
	if _, err := s.stampNow(ctx); err != nil { // уничтожению нужна свежая метка всегда
		t.Fatal(err)
	}
}

// S-13: эпизод молчания переживает рестарт: второго события «молчит» нет.
func TestSilenceSurvivesRestart(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	c.add(11 * time.Minute)
	s.CheckSilence(c.now())
	s.Close()
	s2 := openStore(t, cfg, c)
	c.add(11 * time.Minute)
	s2.CheckSilence(c.now())
	s2.Close()
	if n := len(leavesOf(t, cfg, auditchain.EventSilence)); n != 1 {
		t.Fatalf("событий молчания %d, ожидали 1", n)
	}
}

// S-14: номера вразброс не стоят по 32 КиБ: кусок индекса — карта, пока
// номеров в нём мало, и массив, когда их набралось.
func TestSeqIndexSparse(t *testing.T) {
	var x seqIndex
	for i := uint64(0); i < 512; i++ {
		x.set(1+i*seqChunk, 100+i)
	}
	for i := uint64(0); i < 512; i++ {
		if got := x.get(1 + i*seqChunk); got != 100+i {
			t.Fatalf("номер %d: %d", 1+i*seqChunk, got)
		}
		if x.chunks[i].dense != nil {
			t.Fatalf("кусок %d с одним номером — массив на 32 КиБ", i)
		}
	}
	for q := uint64(seqChunk * 1000); q < seqChunk*1000+seqDenseAt+10; q++ {
		x.set(q, q)
	}
	if x.chunks[1000].dense == nil {
		t.Fatal("плотный кусок остался картой")
	}
	for q := uint64(seqChunk * 1000); q < seqChunk*1000+seqDenseAt+10; q++ {
		if x.get(q) != q {
			t.Fatalf("номер %d потерян при переходе в массив", q)
		}
	}
}

// K-01: часы хоста отстали на 30 дней в момент заявки. Срок ожидания всё
// равно отмеряется от времени TSA: после возврата часов ключ не уничтожается
// раньше, чем через 7 дней по TSA. Раньше срок = отставшие часы + 7 дней
// давно прошёл, и ключ уничтожался сразу.
func TestDestroyWindowFromTSATime(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	tsaClock := newClock()
	tsaClock.add(30 * 24 * time.Hour)
	s.tsaLocal.Now = tsaClock.now
	ctx := context.Background()
	ingest(t, s, "abs-core", 1, 1)
	scope := "abs-core/2026-09"
	if err := s.Deactivate(true, scope); err != nil {
		t.Fatal(err)
	}
	const wait = 7 * 24 * time.Hour
	ki, err := s.ScheduleDestroy(ctx, scope, wait, []keyring.Approval{{Who: "operator"}, {Who: "security"}})
	if err != nil {
		t.Fatal(err)
	}
	if ki.DestroyAfter.Before(tsaClock.now().Add(wait)) {
		t.Fatalf("срок %v отмерен не от времени TSA %v", ki.DestroyAfter, tsaClock.now())
	}
	c.set(tsaClock.now()) // часы хоста вернули
	c.add(time.Minute)
	tsaClock.add(time.Minute)
	if _, err := s.CompleteDue(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.keyInfo(scope); got.State != keyring.Pending {
		t.Fatalf("ключ уничтожен до срока: %v", got.State)
	}
	c.add(wait)
	tsaClock.add(wait)
	if _, err := s.CompleteDue(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.keyInfo(scope); got.State != keyring.Destroyed {
		t.Fatalf("после срока ключ не уничтожен: %v", got.State)
	}
}

// K-04: зеркало корней недоступно (упавшая машина, NFS) — хранилище
// стартует: корни читаются из roots_dir. Раньше старт отказывал.
func TestMirrorDownDoesNotStopStart(t *testing.T) {
	c := newClock()
	mirror := t.TempDir()
	cfg := testConfig(t, func(c *config.Config) { c.Keys.RootsMirrorDir = mirror })
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	s.Close()
	os.RemoveAll(mirror)
	s2 := openStore(t, cfg, c)
	if s2.Status().RootsUnreachable == "" {
		t.Fatal("недоступное зеркало корней не видно в статусе")
	}
	mustStamp(t, s2)
	b, err := s2.Proof("abs-core", 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.Verify(b, trustOf(t, s2)); !r.Valid() || !r.BodyOpened {
		t.Fatalf("без зеркала:\n%s", r.Text())
	}
}

// Z-06: резерв ключей недоступен как раз тогда, когда при подъёме надо
// завести ключ месяца (за неделю до конца — следующего). Хранилище
// поднимается: ключ заведён, но не выдаётся, пока копия не пройдёт, а её
// повторит обслуживание. Раньше подъём падал с ErrBackupPending, и
// хранилище не стартовало вовсе, пока резерв не вернётся (нашла симуляция
// с падениями).
func TestStartsWhileKeyBackupUnreachable(t *testing.T) {
	c := newClock()
	c.set(time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC))
	backup := t.TempDir()
	cfg := testConfig(t, func(c *config.Config) { c.Keys.BackupDir = backup })
	s := openStore(t, cfg, c)
	s.Close()
	c.set(time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)) // пора завести ключи октября
	os.Chmod(backup, 0o500)
	t.Cleanup(func() { os.Chmod(backup, 0o700) })
	s2, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true})
	if err != nil {
		t.Fatalf("не поднялось при недоступном резерве: %v", err)
	}
	t.Cleanup(func() { s2.Close() })
	os.Chmod(backup, 0o700)
	s2.Maintain(c.now()) // копия прошла
	mustStamp(t, s2)
	ingest(t, s2, "abs-core", 1, 1)
	for _, ki := range s2.Keys() {
		if !ki.Confirmed {
			t.Fatalf("после возврата резерва ключ %s не в резерве", ki.Scope)
		}
	}
}

// T-04: лист цепи подменён вместе с CRC кадра. Подъём сверяет листья
// каждого звена с его корнем и не стартует: раньше подменённый лист уходил
// в индексы и в сверку кейринга с цепью.
func TestTamperedLeafStopsStart(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 2)
	s.Close()
	_, chainDir, _ := dirs(cfg)
	segs, _ := filepath.Glob(filepath.Join(chainDir, "leaves_*.log"))
	if len(segs) == 0 {
		t.Fatal("нет файлов листьев")
	}
	data, err := os.ReadFile(segs[0])
	if err != nil {
		t.Fatal(err)
	}
	// Второй кадр: тело начинается с байта домена и времени листа (8 байт).
	// Сдвиг времени на наносекунду лист не ломает — меняет только его хэш.
	off, n := 0, -1
	for i := 0; i <= 1; i++ {
		if off+8 > len(data) {
			t.Fatal("в файле меньше двух листьев")
		}
		n = int(binary.BigEndian.Uint32(data[off : off+4]))
		if i < 1 {
			off += 8 + n
		}
	}
	body := data[off+4 : off+4+n]
	body[8] ^= 1
	binary.BigEndian.PutUint32(data[off+4+n:off+8+n], crc32.ChecksumIEEE(body))
	if err := os.WriteFile(segs[0], data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = reopen(cfg, c)
	if err == nil {
		t.Fatal("подменённый лист цепи принят при подъёме")
	}
	if !strings.Contains(err.Error(), "a leaf was replaced") {
		t.Fatalf("подъём упал не на сверке корня: %v", err)
	}
}

// Q-03: часы хоста впереди TSA (тревога evidencestore_receive_clock_capped):
// время приёма зажато окном по якорю, а листья событий (пропуск номеров,
// хвосты, токен, «сборщик пропал», молчание) берут часы хоста как есть.
// Время звена — время его последнего листа, и звено, которое кончается таким
// событием, «позже срока» обещания: esverify -promise обвиняет честное
// хранилище в нарушенном обещании.
func TestHostClockAheadKeepsPromise(t *testing.T) {
	tsaClock := newClock()
	host := newClock()
	host.add(5 * time.Minute) // часы хоста впереди TSA на 5 минут
	s, err := Open(testConfig(t), Options{Logger: quiet, Now: host.now, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.tsaLocal.Now = tsaClock.now
	s.needAnchor = true // как в serve с TSA: приём только по якорю
	mustStamp(t, s)     // якорь по TSA
	ingest(t, s, "abs-core", 1, 1)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	res := ingest(t, s, "abs-core", 3, 3) // номер 2 пропущен: за уликой — событие пропуска
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	tsaClock.add(time.Minute)
	host.add(time.Minute)
	mustStamp(t, s) // T2

	b, err := s.Proof("abs-core", 3, false)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, trustOf(t, s))
	if !r.Valid() {
		t.Fatalf("пакет не проходит:\n%s", r.Text())
	}
	p := *res[0].Promise
	if err := proof.VerifyPromise(p, nil); err != nil {
		t.Fatal(err)
	}
	var linkTime int64
	for _, l := range b.Links {
		if l.Seq == r.LinkSeq {
			linkTime = l.UnixNano
		}
	}
	t.Logf("принята %s, срок %s, время звена %s", time.Unix(0, p.ReceivedAt).UTC(), time.Unix(0, p.Deadline).UTC(), time.Unix(0, linkTime).UTC())
	if dir := os.Getenv("ES_PROMISE_DUMP"); dir != "" { // для прогона esverify -promise
		bj, _ := json.Marshal(b)
		pj, _ := json.Marshal(p)
		os.WriteFile(filepath.Join(dir, "proof.json"), bj, 0o600)
		os.WriteFile(filepath.Join(dir, "promise.json"), pj, 0o600)
		os.WriteFile(filepath.Join(dir, "store.pub"), []byte(s.PublicKey()+"\n"), 0o600)
		os.WriteFile(filepath.Join(dir, "tsa-root.crt"), s.TSARoot(), 0o600)
	}
	if err := proof.CheckPromise(p, r, b, false); err != nil {
		t.Errorf("честное хранилище «нарушило» обещание: %v", err)
	}
}

// Q-49 (заход 27.10, третий): запись, время приёма которой взято по
// прежнему якорю (монотонные часы стояли 9 минут), а лист лёг в цепь после
// хвостов ПОВТОРНОЙ метки (errClockLost). Так бывает с записью, которая на
// fsync журнала улик в момент первого ответа TSA: повтор метки кладёт
// хвосты сразу, а её лист — через миллисекунды. Здесь «миллисекунды»
// растянуты замком scopeMu (Ingest берёт его после времени приёма и до
// журнала улик; метке он не нужен). README: «a TSA answer whose time lies
// beyond the receive-time window is not used: the store stamps again, so
// whatever arrived during that request lies before the time-stamp».
func TestClockLostRetryWaitsForRecordInFlight(t *testing.T) {
	clk := newClock() // 10:00
	var mono atomic.Int64
	mono.Store(int64(1000 * time.Hour))
	advance := func(real, monoD time.Duration) {
		clk.add(real)
		mono.Add(int64(monoD))
	}
	cfg := testConfig(t)
	s, err := Open(cfg, Options{Logger: quiet, Now: clk.now, NoBackground: true, Mono: func() time.Duration { return time.Duration(mono.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.tsaLocal.Now = clk.now

	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // A, 10:00 — якорь
	s.needAnchor = true
	advance(time.Minute, time.Minute)
	ingest(t, s, "abs-core", 2, 2) // 10:01
	advance(9*time.Minute, 0)      // машина стояла 9 минут: 10:10 по TSA и хосту

	// Запись 3: время приёма взято (по прежнему якорю — около 10:01), до
	// журнала улик она ещё не дошла.
	s.scopeMu.Lock()
	done := make(chan []Result, 1)
	go func() {
		res, err := s.Ingest("abs-core", []Incoming{{Seq: 3, Body: []byte("abs-core event 3")}})
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()
	for {
		s.mu.Lock()
		taken := s.sources["abs-core"].inflight[3]
		s.mu.Unlock()
		if taken {
			break
		}
		time.Sleep(time.Millisecond)
	}
	// Метка B: первый ответ (10:10) — позже окна по якорю, токен не ложится,
	// якорь по нему, повтор кладёт новые хвосты. Пока идёт второй запрос,
	// запись 3 доходит до цепи.
	// fsync записи 3 кончается через 50 мс после первого запроса к TSA —
	// уже после первого ответа; второй запрос ждёт, пока она ляжет в цепь
	// (иначе исход зависел бы от того, кто раньше возьмёт chainMu).
	asked := 0
	var res []Result
	s.tsaLocal.Now = func() time.Time {
		asked++
		switch asked {
		case 1:
			time.AfterFunc(50*time.Millisecond, s.scopeMu.Unlock)
		case 2:
			res = <-done
		}
		return clk.now()
	}
	if _, err := s.StampNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.tsaLocal.Now = clk.now
	if asked != 2 {
		t.Fatalf("запросов к TSA: %d, ждали 2 (повтор после потери хода часов)", asked)
	}
	if len(res) != 1 || res[0].Promise == nil {
		t.Fatalf("запись 3 не принята: %+v", res)
	}
	p := *res[0].Promise
	recv3 := time.Unix(0, p.ReceivedAt).UTC()
	advance(10*time.Minute, 10*time.Minute)
	ingest(t, s, "abs-core", 4, 4)
	mustStamp(t, s) // C, 10:20

	tr := trustOf(t, s)
	// Обещание по записи 3.
	b, err := s.Proof("abs-core", 3, false)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, tr)
	perr := proof.CheckPromise(p, r, b, false)
	var linkTimes []string
	for _, l := range b.Links {
		linkTimes = append(linkTimes, time.Unix(0, l.UnixNano).UTC().Format("15:04:05"))
	}
	t.Logf("запись 3: принята %s (срок %s), звено %d; пакет %s; звенья %d…: %v; обещание: %v",
		recv3.Format("15:04:05"), time.Unix(0, p.Deadline).UTC().Format("15:04:05"), r.LinkSeq, r.Verdict(), b.Links[0].Seq, linkTimes, perr)

	// Пакет за окно вокруг времени приёма записи 3.
	from, to := recv3.Add(-30*time.Second), recv3.Add(30*time.Second)
	w, err := s.ProofWindow(from, to, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	wr := proof.VerifyWindow(w, tr, from, to)
	sb, err := s.ProofSource("abs-core", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	sr := proof.VerifySource(sb, tr, from, to)
	t.Logf("пакет за окно %s – %s: %s; пакет по источнику: %s", from.Format("15:04:05"), to.Format("15:04:05"), wr.Verdict(), sr.Verdict())
	if !wr.Valid() {
		for _, c := range wr.Checks {
			if !c.OK {
				t.Logf("  ✘ %s — %s", c.Name, c.Detail)
			}
		}
	}
	if perr != nil || !r.Valid() {
		t.Errorf("честное хранилище: esverify -promise обвиняет запись 3: %v", perr)
	}
	if !wr.Valid() || !sr.Valid() {
		t.Errorf("честное хранилище: пакет за окно (%s) или по источнику (%s) не проходит", wr.Verdict(), sr.Verdict())
	}
}

// Q-49: пока якорь переставляется после потери хода монотонных часов,
// приём на паузе: новая запись получает ErrNoAnchor (сборщик повторит), а
// не время по прежнему, отставшему якорю. Пауза кончается, когда записи в
// пути легли в цепь.
func TestReanchorPausesIntake(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	mustStamp(t, s)
	s.needAnchor = true
	s.scopeMu.Lock() // запись 1 взяла время приёма, до журнала улик не дошла
	done := make(chan error, 1)
	go func() {
		_, err := s.Ingest("abs-core", []Incoming{{Seq: 1, Body: []byte("in flight")}})
		done <- err
	}()
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
		}
	}
	locked := func(f func() bool) func() bool {
		return func() bool { s.mu.Lock(); defer s.mu.Unlock(); return f() }
	}
	waitFor("запись 1 не в пути", locked(func() bool { return s.sources["abs-core"].inflight[1] }))
	reanchored := make(chan struct{})
	go func() { s.reanchor(c.now(), s.mono(), 0); close(reanchored) }()
	waitFor("перестановка якоря не началась", locked(func() bool { return s.reanchoring }))
	during := make(chan error, 1)
	go func() {
		_, err := s.Ingest("abs-core", []Incoming{{Seq: 2, Body: []byte("during")}})
		during <- err
	}()
	select {
	case err := <-during:
		if !errors.Is(err, ErrNoAnchor) {
			t.Fatalf("приём во время перестановки якоря: %v", err)
		}
	case <-time.After(5 * time.Second):
		// Запись взяла время приёма по прежнему якорю и ждёт журнал улик.
		s.scopeMu.Unlock()
		t.Fatal("приём во время перестановки якоря не на паузе")
	}
	s.scopeMu.Unlock()
	<-reanchored
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 2, 2)
}

// Q-47: первая метка вышла, открывающая (вторая) — нет: TSA пропала между
// ними. Якорь свежий, но приём закрыт, и keepAnchor повторяет открывающую
// метку, пока TSA не ответит.
func TestOpeningStampRetried(t *testing.T) {
	saved := anchorRetry
	anchorRetry = 5 * time.Millisecond
	defer func() { anchorRetry = saved }()
	s, err := Open(testConfig(t), Options{Logger: quiet, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.needAnchor = true
	var calls atomic.Int32
	var up atomic.Bool
	s.tsaLocal.Now = func() time.Time {
		if calls.Add(1) > 1 && !up.Load() {
			return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC) // TSA пропала
		}
		return time.Now()
	}
	if _, err := s.Stamp(context.Background()); err == nil {
		t.Fatal("ПАРНЫЙ КОНТРОЛЬ: открывающая метка вышла при пропавшей TSA")
	}
	if err := s.anchored(); !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("приём открыт одной первой меткой: %v", err)
	}
	s.wg.Add(1)
	go s.keepAnchor()
	up.Store(true)
	for deadline := time.Now().Add(5 * time.Second); s.anchored() != nil; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("TSA ответила, а приём так и закрыт")
		}
	}
}

// Q-47 (J-03): событие взяло время до якоря (часы хоста впереди на 5 минут,
// как есть) и ждёт цепь, а якорь тем временем ставится. В цепь оно ложится
// со временем по новому якорю: иначе лист с часами хоста лёг бы после
// листьев нового якоря, в звенья, которые считает сверка обещания.
func TestEventWaitingForChainTakesNewAnchor(t *testing.T) {
	tsaClock := newClock()
	host := newClock()
	host.add(5 * time.Minute)
	s, err := Open(testConfig(t), Options{Logger: quiet, Now: host.now, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.chainMu.Lock()
	done := make(chan uint64, 1)
	go func() { done <- s.appendEvent(auditchain.EventSilence, "abs-core", "", nil) }()
	time.Sleep(20 * time.Millisecond) // событие взяло время и ждёт цепь
	s.anchorClock(tsaClock.now(), s.mono(), 0)
	s.chainMu.Unlock()
	num := <-done
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	leaves, err := auditchain.ReadLeaves(s.chainDir, num, 1)
	if err != nil {
		t.Fatal(err)
	}
	if at := time.Unix(0, leaves[0].UnixNano); at.After(tsaClock.now().Add(time.Minute)) {
		t.Fatalf("событие легло со временем %v — часы хоста как есть, а не по якорю %v", at.UTC(), tsaClock.now())
	}
}

// Q-50: запись, принятая во время первых меток нового хранилища, не ложится
// до токена той, что открыла приём (без T1 esverify -promise обещание не
// сверяет). Приём пробуется на каждом обращении к монотонным часам после
// ответа TSA, все принятые записи проходят сверку обещания.
func TestIntakeOpensAfterFirstTokenLeaf(t *testing.T) {
	clk := newClock()
	var monoV atomic.Int64
	monoV.Store(int64(1000 * time.Hour))
	var signed, injecting atomic.Bool
	var s *Store
	var seq uint64
	var promises []proof.Promise
	mono := func() time.Duration {
		// Обращения к часам после ответа TSA — вне замков хранилища; сам
		// Ingest тоже зовёт часы (под s.mu) — туда не вкладываемся.
		if signed.Load() && injecting.CompareAndSwap(false, true) {
			seq++
			if res, err := s.Ingest("abs-core", []Incoming{{Seq: seq, Body: []byte(fmt.Sprintf("abs-core event %d", seq))}}); err == nil {
				promises = append(promises, *res[0].Promise)
			} else {
				seq--
			}
			injecting.Store(false)
		}
		return time.Duration(monoV.Load())
	}
	var err error
	s, err = Open(testConfig(t), Options{Logger: quiet, Now: clk.now, NoBackground: true, Mono: mono})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.needAnchor = true // как в serve с TSA: приём только по якорю
	s.tsaLocal.Now = func() time.Time { signed.Store(true); return clk.now() }
	mustStamp(t, s) // первая метка нового хранилища
	signed.Store(false)
	s.tsaLocal.Now = clk.now
	ingest(t, s, "abs-core", seq+1, seq+1)
	for _, r := range ingest(t, s, "abs-core", seq+2, seq+2) {
		promises = append(promises, *r.Promise)
	}
	clk.add(time.Minute)
	monoV.Add(int64(time.Minute))
	mustStamp(t, s)
	tr := trustOf(t, s)
	for _, p := range promises {
		b, err := s.Proof("abs-core", p.Seq, false)
		if err != nil {
			t.Fatal(err)
		}
		r := proof.Verify(b, tr)
		if err := proof.CheckPromise(p, r, b, false); !r.Valid() || err != nil {
			t.Fatalf("запись %d: пакет %s, T1 %v, обещание: %v", p.Seq, r.Verdict(), r.Lower, err)
		}
	}
}

// Q-47: первая метка процесса при часах хоста впереди TSA на 5 минут. Пока
// идёт её запрос, якоря нет, и событие в цепи (пропуск по пульсу, звено
// свернул тик) получает часы хоста как есть. Приём открывает только
// следующая метка, с хвостами при якоре: у записи T1 — она, и сверка
// обещания от головы под ней этого звена не считает.
func TestIntakeOpensAfterSecondStamp(t *testing.T) {
	tsaClock := newClock()
	host := newClock()
	host.add(5 * time.Minute)
	s, err := Open(testConfig(t), Options{Logger: quiet, Now: host.now, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.needAnchor = true
	s.tsaLocal.Now = func() time.Time {
		if err := s.Issued("abs-core", 2); err != nil {
			t.Error(err)
		}
		if err := s.flush(); err != nil {
			t.Error(err)
		}
		return tsaClock.now()
	}
	if _, _, err := s.stampOnce(context.Background(), true); err != nil { // первая: только якорь
		t.Fatal(err)
	}
	s.tsaLocal.Now = tsaClock.now
	if _, err := s.Ingest("abs-core", []Incoming{{Seq: 3, Body: []byte("too early")}}); !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("приём после первой метки: %v", err)
	}
	mustStamp(t, s) // вторая — с хвостами при якоре
	res := ingest(t, s, "abs-core", 3, 3)
	tsaClock.add(time.Minute)
	host.add(time.Minute)
	mustStamp(t, s)
	b, err := s.Proof("abs-core", 3, false)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, trustOf(t, s))
	if err := proof.CheckPromise(*res[0].Promise, r, b, false); !r.Valid() || err != nil {
		t.Fatalf("пакет %s; обещание: %v", r.Verdict(), err)
	}
}

// Монотонные часы стояли (сон хоста, пауза ВМ: CLOCK_MONOTONIC в Linux во
// сне не идёт), и время приёма отстаёт от времени TSA на всю паузу до
// следующей метки. Запись, принятая, пока шёл запрос этой метки, легла бы
// после заверенного звена со временем внутри окна, которое метка закрывает,
// и пакеты за окно и по источнику её бы не показали. Метка, чьё время позже
// окна по якорю, в цепь не ложится: якорь — по ней, метка повторяется с
// новыми хвостами. Якорь просит метки сразу, как часы хоста ушли вперёд
// оценки по нему.
func TestMonoPauseKeepsWindowRecords(t *testing.T) {
	clk := newClock() // истинное время = часы хоста = время TSA, 10:00
	var mono atomic.Int64
	mono.Store(int64(1000 * time.Hour))
	advance := func(real, monoD time.Duration) {
		clk.add(real)
		mono.Add(int64(monoD))
	}
	cfg := testConfig(t)
	s, err := Open(cfg, Options{Logger: quiet, Now: clk.now, NoBackground: true, Mono: func() time.Duration { return time.Duration(mono.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.tsaLocal.Now = clk.now

	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s)     // A, 10:00 — якорь
	s.needAnchor = true // как в serve с TSA: приём только по якорю
	advance(time.Minute, time.Minute)
	ingest(t, s, "abs-core", 2, 2) // 10:01
	if s.anchorStale() {
		t.Fatal("якорь минутной давности просит метки")
	}
	advance(9*time.Minute, 0) // машина стояла 9 минут
	if !s.anchorStale() {
		t.Error("часы хоста ушли вперёд оценки по якорю на 9 минут, а якорь не просит метки")
	}
	ingest(t, s, "abs-core", 3, 3) // 10:10 по TSA и хосту

	// Метка B (10:10); пока шёл запрос, пришла запись 4.
	inject := true
	s.tsaLocal.Now = func() time.Time {
		if inject {
			inject = false
			ingest(t, s, "abs-core", 4, 4)
			if err := s.flush(); err != nil {
				t.Fatal(err)
			}
		}
		return clk.now()
	}
	mustStamp(t, s)
	s.tsaLocal.Now = clk.now
	if s.anchorStale() {
		t.Error("якорь по свежей метке просит метки")
	}
	advance(10*time.Minute, 10*time.Minute)
	ingest(t, s, "abs-core", 5, 5)
	mustStamp(t, s) // C, 10:20

	from, to := clockAt(10, 0, 30), clockAt(10, 5, 0)
	var recv4 time.Time
	for _, l := range leavesOf(t, cfg, auditchain.EventEvidence) {
		if l.Scope == "abs-core" && l.Subject == "4" {
			recv4 = time.Unix(0, l.UnixNano).UTC()
		}
	}
	if recv4.Before(from) || recv4.After(to) {
		t.Fatalf("время приёма записи 4 (%s) вне окна %s–%s: пауза не воспроизведена", recv4, from, to)
	}
	tr := trustOf(t, s)
	w, err := s.ProofWindow(from, to, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	wr := proof.VerifyWindow(w, tr, from, to)
	var last uint64
	for _, src := range wr.Sources {
		if src.Name == "abs-core" {
			last = src.LastSeq
		}
	}
	if !wr.Valid() || last < 4 {
		t.Fatalf("пакет за окно без записи 4 (время приёма %s):\n%s", recv4, wr.Text())
	}
	sb, err := s.ProofSource("abs-core", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sr := proof.VerifySource(sb, tr, from, to); !sr.Valid() || sr.LastSeq < 4 {
		t.Fatalf("пакет по источнику без записи 4:\n%s", sr.Text())
	}
	w2, err := s.ProofWindow(from, clockAt(10, 17, 0), "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifyWindow(w2, tr, from, clockAt(10, 17, 0)); !r.Valid() {
		t.Fatalf("пакет за окно 10:00:30–10:17:\n%s", r.Text())
	}

	// Короткая пауза (5 с, миграция ВМ) — тоже: первый токен не ложится,
	// метка повторяется — два запроса к TSA, один токен в цепи.
	advance(time.Minute, time.Minute)
	ingest(t, s, "abs-core", 6, 6)
	advance(5*time.Second, 0)
	asked := 0
	s.tsaLocal.Now = func() time.Time { asked++; return clk.now() }
	n := len(s.tokens)
	mustStamp(t, s)
	if asked != 2 || len(s.tokens) != n+1 {
		t.Fatalf("после паузы 5 с: запросов к TSA %d, меток %d → %d", asked, n, len(s.tokens))
	}
}
