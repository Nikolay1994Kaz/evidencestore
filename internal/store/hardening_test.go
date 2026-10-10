package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"evidencestore/internal/auditchain"
	"evidencestore/internal/config"
	"evidencestore/internal/evlog"
	"evidencestore/internal/keyring"
	"evidencestore/internal/metrics"
	"evidencestore/internal/proof"
	"evidencestore/internal/ship"
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
		c.Keys.BackupDir = filepath.Join(t.TempDir(), "keys-backup")
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
		files, heads, err := listReplica(ctx, remote)
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
	_, heads, err := listReplica(ctx, remote)
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

	cfg.Keys.BackupDir = filepath.Join(t.TempDir(), "keys-backup") // резерв включили позже
	s2 := openStore(t, cfg, c)
	s2.Close()
	_, chainDir, _ := dirs(cfg)
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

// K-02: init при ключах в резерве — отказ: так выглядит хранилище, потерявшее
// data_dir, а новый пустой кейринг затёр бы в резерве ключи всех месяцев.
func TestInitRefusesWithKeysInBackup(t *testing.T) {
	backupDir := filepath.Join(t.TempDir(), "keys-backup")
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
	backupDir := filepath.Join(t.TempDir(), "keys-backup")
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
	mirror := filepath.Join(t.TempDir(), "mirror")
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
	if !strings.Contains(err.Error(), "лист подменён") {
		t.Fatalf("подъём упал не на сверке корня: %v", err)
	}
}
