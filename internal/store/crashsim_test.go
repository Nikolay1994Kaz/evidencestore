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
	"log/slog"
	"maps"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evlog"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/ship"
)

// Симуляция хранилища с падениями. Честные клиенты (сборщики двух
// источников syslog и журнала гейтвея Pipelock — настоящий бортовой журнал
// v3.6.0 из тестовых данных) шлют пачки: новые записи, иногда (syslog) с
// пропущенными номерами, неподтверждённые — снова, изредка принятую —
// повтором. Хранилище живёт в
// виртуальном времени, как serve: приём ждёт свежей метки TSA, фоновые циклы
// идут шагами — звено каждую секунду, якорь и молчание раз в 10 с,
// обслуживание ключей раз в минуту, метка раз в tsa.every. Время начинается
// за 20 минут до конца месяца (закрываются прошлые ключи) или за 7 дней до
// него (ключи следующего месяца заводятся по ходу сценария).
//
// Падение — снимок диска (data_dir, корни, резерв ключей) в точке записи:
// перед листьями, звеном или головой цепи, перед копией keyring.dat в
// резерв, в конце операции до ответа клиенту (журнал улик уже на диске,
// цепь — в памяти); или посреди записи — у файла, дописанного последним,
// на диске остаётся начало; если писалась голова цепи — её слот испорчен;
// в снимке бывают и недописанные временные файлы (.tmp). Сегменты журнала
// улик и файлы листьев цепи в двух третях сценариев маленькие: ротация идёт
// часто и тоже под падениями. Хранилище поднимается из снимка; ответ, не
// дошедший до падения, клиент не видит и шлёт записи снова. Бывают и
// штатные перезапуски, и работа оператора: keyring.dat, поднятый из
// резерва (так велит README после потери файла), и откат keyring.dat к
// старой копии по ошибке — после него подъём из резерва; резерв ключей на
// время недоступен; чужая установка сборщика стучится с тем же
// сертификатом; заявка двух людей на уничтожение закрытого месяца, отмена,
// уничтожение корней-сирот — и падения посреди поворота корня (новый корень
// заведён, старый ещё не уничтожен). Копия наружу (каталог — другая машина,
// падения её не трогают) дотягивается раз в минуту, падения бывают и
// посреди отправки кусков; диск data_dir теряется — оператор поднимает
// журнал и цепь из копии, keyring.dat и sign.key — из резерва. Врущий диск:
// в снимке пропадает то, что уже прошло fsync, — последние записи журнала
// улик или последнее звено цепи. В половине сценариев резерв недоступен как раз на смене
// ключа (заведение следующего месяца или закрытие прошлого), и в половине
// из них keyring.dat поднимается из резерва в окне после смены: иначе
// такое совпадение — редкость. Четверть сценариев — спокойные: ни падений,
// ни перезапусков, ни работы оператора (перезапуск сам подтверждает копию
// ключей и прятал бы то, что должно делать обслуживание).
//
// Эталон:
//   - хранилище поднимается после любого падения и с keyring.dat из резерва
//     в любой момент — в том числе после попытки отката (резерв не затёрт);
//   - выданное обещание выполнено: пакет доказательств проходит проверку
//     как в esverify (обе границы времени по меткам TSA), позиция,
//     отпечаток и время приёма те же, звено не позже срока;
//   - повтор принятого номера — «duplicate» с тем же обещанием байт в байт;
//   - честному клиенту — ни конфликта номера, ни отказа эпохи, ни ошибки
//     (кроме «ждите»: свежей метки, копии ключа в резерве); чужой установке
//     после закрепления — всегда отказ;
//   - всё посланное в конце принято; каждый номер — в журнале улик один раз
//     и листом в цепи; тело — то, что слал клиент;
//   - каждый пропущенный клиентом номер — событие пропуска в цепи; кроме
//     предела README: падение посреди записи листьев цепи уносит событие,
//     а улика со следующим номером уцелела — такие номера отмечаются сразу
//     после подъёма (simClient.gapLost);
//   - «источник молчит» — одно событие на эпизод;
//   - у каждой улики гейтвея — ровно один вердикт в цепи, и он тот же, что
//     у чистого прогона тех же записей в том же порядке (после падений
//     состояние проверки поднимается из цепи); пакет проходит проверку с
//     ключом гейтвея;
//   - квитанции ключей в цепи догоняют кейринг; прошлые месяцы закрыты;
//   - тело выдаётся, пока ключ жив, и не выдаётся, когда он ждёт уничтожения
//     или уничтожен (пакет при этом доказывает существование и неизменность);
//     уничтожение после падений доходит до конца; уничтоженный ключ не
//     поднимается ни из одной прежней копии keyring.dat (ни из резерва);
//   - потеря диска: хранилище поднимается из копии; принятое после последней
//     копии потеряно, и это видно — событием пропуска; врущий диск — либо
//     громкий отказ при подъёме или копии (и подъём из копии), либо потеря
//     видна пропуском.
//
// STORESIM_SEEDS — сценариев, STORESIM_SEED — один (с полным ходом),
// STORESIM_STEPS — шагов в сценарии, STORESIM_WORKERS — параллельных
// подтестов (4).
func TestStoreCrashSim(t *testing.T) {
	seeds, steps := 40, 200
	if raceBuild {
		seeds = 6
	}
	if v, err := strconv.Atoi(os.Getenv("STORESIM_SEEDS")); err == nil && v > 0 {
		seeds = v
	}
	if v, err := strconv.Atoi(os.Getenv("STORESIM_STEPS")); err == nil && v > 0 {
		steps = v
	}
	only, single := os.LookupEnv("STORESIM_SEED")
	workers := 4
	if v, err := strconv.Atoi(os.Getenv("STORESIM_WORKERS")); err == nil && v > 0 {
		workers = v
	}
	for w := range workers {
		t.Run(fmt.Sprintf("w%d", w), func(t *testing.T) {
			t.Parallel()
			failed, total, kinds := 0, 0, map[string]int{}
			var stats simStats
			for i := w; i < seeds; i += workers {
				seed := uint64(i) + 1
				if single {
					if w > 0 || i > 0 {
						break
					}
					seed, _ = strconv.ParseUint(only, 10, 64)
				}
				total++
				msg, st := runStoreSim(t, seed, steps)
				stats.add(st)
				if msg != "" {
					failed++
					kind, _, _ := strings.Cut(msg, " ")
					kind, _, _ = strings.Cut(kind, ":")
					kinds[kind]++
					if kinds[kind] <= 2 && failed <= 3 {
						t.Errorf("STORESIM_SEED=%d:\n%s", seed, msg)
					}
				}
			}
			if failed > 0 {
				t.Errorf("провалено %d из %d сценариев; виды: %v", failed, total, kinds)
			}
			t.Logf("сценариев %d: %s", total, stats)
		})
	}
}

// simStats — что пережило хранилище за сценарии (печатается с -v).
type simStats struct {
	crashes, torn, restarts, restores, rollbacks int
	headTears, litter                            int // обрыв слота головы; недописанные .tmp в снимке
	evSegments, leafFiles                        int // сегментов журнала и файлов листьев в конце (ротация)
	schedules, cancels, orphanRuns, destroyed    int // заявки на уничтожение, отмены, уничтожение сирот; ключей уничтожено окончательно
	rootCrashes, orphansSeen                     int // падений посреди поворота корня; подъёмов с сиротами
	drs, lies, loud, drLost                      int // подъёмов из копии; врущий диск; громких отказов; принятых, потерянных с диском
	divergedCopies, relocations                  int // копия отказала: data_dir её не продолжает; копия переведена на новое место
	copyDeaths                                   int // диск потерян вместе с падением посреди прохода копии
	rushes, rushBatches                          int // заходов параллельной работы; пачек, посланных в них
	twins, rogueRaces                            int // одна пачка двумя запросами сразу; чужая установка во время приёма
}

func (a *simStats) add(b simStats) {
	a.crashes += b.crashes
	a.torn += b.torn
	a.restarts += b.restarts
	a.restores += b.restores
	a.rollbacks += b.rollbacks
	a.headTears += b.headTears
	a.litter += b.litter
	a.evSegments += b.evSegments
	a.leafFiles += b.leafFiles
	a.schedules += b.schedules
	a.cancels += b.cancels
	a.orphanRuns += b.orphanRuns
	a.destroyed += b.destroyed
	a.rootCrashes += b.rootCrashes
	a.orphansSeen += b.orphansSeen
	a.drs += b.drs
	a.lies += b.lies
	a.loud += b.loud
	a.drLost += b.drLost
	a.divergedCopies += b.divergedCopies
	a.copyDeaths += b.copyDeaths
	a.relocations += b.relocations
	a.rushes += b.rushes
	a.rushBatches += b.rushBatches
	a.twins += b.twins
	a.rogueRaces += b.rogueRaces
}

func (a simStats) String() string {
	return fmt.Sprintf("падений %d (посреди записи %d, посреди записи головы %d, с недописанными .tmp %d), штатных перезапусков %d, keyring.dat из резерва %d, откатов keyring.dat %d; сегментов журнала %d, файлов листьев %d; заявок на уничтожение %d, отмен %d, уничтожений сирот %d, ключей уничтожено %d; падений посреди поворота корня %d, подъёмов с сиротами %d; подъёмов из копии %d, врущий диск %d (громких отказов %d), принятых потеряно с диском %d, копия не продолжается data_dir %d, переведена на новое место %d, диск потерян посреди прохода копии %d; параллельной работы %d заходов (%d пачек, из них двумя запросами сразу %d; чужая установка во время приёма %d)",
		a.crashes, a.torn, a.headTears, a.litter, a.restarts, a.restores, a.rollbacks, a.evSegments, a.leafFiles,
		a.schedules, a.cancels, a.orphanRuns, a.destroyed, a.rootCrashes, a.orphansSeen, a.drs, a.lies, a.loud, a.drLost, a.divergedCopies, a.relocations, a.copyDeaths, a.rushes, a.rushBatches, a.twins, a.rogueRaces)
}

// storeSim — один сценарий.
type storeSim struct {
	t        *testing.T
	root     string // каталоги сценария: удаляются в конце, снимки умерших — сразу
	rng      *mrand.Rand
	clk      *clock
	cfg      *config.Config
	s        *Store
	pub      ed25519.PublicKey
	logBuf   *bytes.Buffer
	logger   *slog.Logger
	clients  []*simClient
	mu       sync.Mutex // trace и failures: в параллельной работе пишут все горутины
	trace    []string
	failures []string
	stats    simStats
	rushing  bool // идёт параллельная работа: падений нет, точки записи пусты
	// rushDirty — после параллельной работы звено ещё не сбрасывалось: тик
	// звена, шедший вместе с приёмом, мог сбросить улики пачки раньше, чем к
	// ним легли события о пропуске, и падение уносит события (предел README).
	rushDirty bool
	// gapsAfterOpen — падение в шаге оператора (stopStore) пришлось на
	// rushDirty: после подъёма — та же поправка, что в crash.
	gapsAfterOpen bool

	// Падение: взведено — снять диск на armed-й точке записи; snap — снимок;
	// armRoots — считаются только точки поворота корня (иначе на поворот,
	// который бывает раз на уничтожение, падение почти не попадает).
	armRoots bool
	armed    int
	points   int
	snap     *config.Config
	snapAt   string
	// sizes — размеры дописываемых файлов (журнал улик, листья, звенья) в
	// прошлой точке: файл, выросший с тех пор, можно оборвать посредине.
	sizes map[string]int64

	lastAnchor, lastMaintain, lastStamp time.Time

	// Работа оператора и отказы диска.
	oldKeyrings  [][]byte // прежние копии keyring.dat: откат и проверка, что уничтоженное не воскресает
	backupLocked bool     // резерв ключей недоступен
	backupFixAt  time.Time
	// Нагрузка на смену ключа: резерв заперт с lockAt до lockUntil, в
	// restoreAt keyring.dat поднимается из резерва (ноль — не будет).
	lockAt, lockUntil, restoreAt time.Time
	calm                         bool  // ни падений, ни перезапусков, ни работы оператора
	evSeg, chainSeg              int64 // пороги сегментов (0 — как в проде)
	repChunk                     int64 // предел куска копии (0 — как в проде): проход рвётся посреди записи

	// Копия наружу и потеря диска.
	remote, remoteRaw ship.Remote // копия с точками падения перед кусками; та же без них
	shipped           bool        // в копии есть подписанная голова
	restoredAt        []time.Time // когда хранилище поднималось из копии
	lastShip          time.Time
	lostFsynced       bool // диск потерял то, что прошло fsync (врущий диск), до подъёма из копии
	diverged          bool // копия громко отказала (data_dir её не продолжает), оператор ещё не пришёл
	// acks — ответов «принято» всего; copied — сколько их было к началу
	// последнего прохода копии, дошедшего до головы: всё принятое до него
	// обязано пережить потерю диска.
	acks   atomic.Int64
	copied int64
}

// simClient — честный сборщик одного источника.
type simClient struct {
	source  string
	epoch   string
	next    uint64
	bodies  map[uint64]string
	unacked []uint64 // слал, ответа не получил (по возрастанию)
	acked   map[uint64]proof.Promise
	ackedAt map[uint64]int64  // порядковый номер ответа «принято» (общий на всех клиентов)
	skipped map[uint64]bool   // номера, которые сборщик пропустил сам (потеря у источника)
	skipAt  map[uint64]int    // где в ходе сценария номер пропущен (для разбора провала)
	gapLost map[uint64]bool   // событие о пропуске унёс обрыв листьев цепи (предел README)
	bound   bool              // хранилище закрепило источник за этим клиентом (ответ получен)
	scope   map[uint64]string // скоуп ключа принятой записи (месяц приёма)
	drLost  map[uint64]bool   // принятые, потерянные вместе с диском (подъём из копии, врущий диск)
	lines   [][]byte          // журнал гейтвея: тело номера q — lines[q-1]; nil — syslog
	rogue   string            // эпоха чужой установки с тем же сертификатом
	rng     *mrand.Rand       // своя случайность клиента в параллельной работе (иначе — общая)
}

func runStoreSim(t *testing.T, seed uint64, steps int) (msg string, stats simStats) {
	rng := mrand.New(mrand.NewPCG(seed, seed*7919))
	start := time.Date(2026, 9, 30, 23, 40, 0, 0, time.UTC) // конец месяца: закрываются прошлые ключи
	if rng.IntN(2) == 0 {
		start = time.Date(2026, 9, 23, 23, 52, 0, 0, time.UTC) // за неделю: заводятся ключи следующего
	}
	root, err := os.MkdirTemp("", "storesim-")
	if err != nil {
		t.Fatal(err)
	}
	m := &storeSim{t: t, root: root, rng: rng, clk: &clock{t: start}, logBuf: &bytes.Buffer{}, armed: -1}
	m.calm = rng.IntN(4) == 0
	if rng.IntN(3) > 0 {
		m.evSeg, m.chainSeg = 3<<10, 4<<10 // ротация каждые десяток записей
	}
	if rng.IntN(3) == 0 {
		m.repChunk = 64 << rng.IntN(4) // кусок копии меньше записи
	}
	if rng.IntN(2) == 0 {
		// Смена ключа — первое обслуживание после: заведение ключей
		// следующего месяца (за 7 дней до конца) или закрытие прошлого.
		change := time.Date(2026, 10, 1, 0, 5, 0, 0, time.UTC)
		if start.Day() == 23 {
			change = time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
		}
		hold := []time.Duration{30 * time.Second, 3 * time.Minute, 10 * time.Minute}[rng.IntN(3)]
		m.lockAt, m.lockUntil = change.Add(-time.Minute), change.Add(hold)
		if rng.IntN(2) == 0 && !m.calm {
			m.restoreAt = change.Add(time.Duration(rng.Int64N(int64(hold + 2*time.Minute))))
		}
	}
	m.logger = slog.New(slog.NewTextHandler(m.logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	m.cfg = &config.Config{
		DataDir: m.newDir("data"), RootsDir: m.newDir("roots"),
		TSA:  config.TSA{URL: "local"},
		Keys: config.Keys{MinWait: config.Duration(time.Nanosecond), BackupDir: m.newDir("backup")},
		Demo: true,
		Sources: []config.Source{
			{Name: "abs-core", ContentType: "syslog", ExpectEvery: config.Duration(10 * time.Minute)},
			{Name: "edge-gw", ContentType: "syslog", ExpectEvery: config.Duration(30 * time.Minute)},
			{Name: "agent-gw", ContentType: config.GatewayContentType, GatewayKey: pipelockKey(t)},
		},
	}
	remoteDir := m.newDir("remote")
	if err := os.MkdirAll(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	m.cfg.Replica.URL = "file://" + remoteDir
	m.cfg.Defaults()
	if err := m.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(m.cfg); err != nil {
		t.Fatal(err)
	}
	if m.remoteRaw, err = ship.OpenRemote(m.cfg.Replica.URL); err != nil {
		t.Fatal(err)
	}
	m.remote = simRemote{m.remoteRaw, m}
	journal := pipelockSession(t)
	for i, src := range m.cfg.Sources {
		var lines [][]byte
		if src.ContentType == config.GatewayContentType {
			lines = journal
		}
		m.clients = append(m.clients, &simClient{lines: lines,
			source: src.Name, epoch: fmt.Sprintf("%032x", seed*16+uint64(i)+1), rogue: fmt.Sprintf("%032x", seed*16+uint64(i)+9), next: 1,
			bodies: map[uint64]string{}, acked: map[uint64]proof.Promise{}, ackedAt: map[uint64]int64{}, skipped: map[uint64]bool{}, skipAt: map[uint64]int{}, gapLost: map[uint64]bool{}, scope: map[uint64]string{}, drLost: map[uint64]bool{},
		})
	}
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprintf("паника: %v\n%s", r, m.tail())
		}
		stats = m.stats
		if m.s != nil {
			m.s.Close()
		}
		m.unlockBackup() // права на место: иначе каталог не удалить
		os.RemoveAll(m.root)
	}()
	m.open()
	m.saveKeyring()
	for range steps {
		if len(m.failures) > 0 {
			break
		}
		m.step()
	}
	if len(m.failures) == 0 {
		m.quiesce()
	}
	if len(m.failures) == 0 {
		m.check()
	}
	if len(m.failures) == 0 {
		return "", m.stats
	}
	return strings.Join(m.failures[:min(len(m.failures), 6)], "\n") + "\n" + m.tail(), m.stats
}

func (m *storeSim) tail() string {
	from := max(0, len(m.trace)-50)
	if _, single := os.LookupEnv("STORESIM_SEED"); single {
		from = 0
	}
	log := m.logBuf.String()
	if len(log) > 5000 {
		log = "…" + log[len(log)-5000:]
	}
	return "ход (последние шаги):\n  " + strings.Join(m.trace[from:], "\n  ") + "\nжурнал хранилища:\n" + log
}

func (m *storeSim) note(format string, args ...any) {
	line := m.clk.now().Format("15:04:05.0 ") + fmt.Sprintf(format, args...)
	m.mu.Lock()
	m.trace = append(m.trace, line)
	m.mu.Unlock()
}

func (m *storeSim) traceLen() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.trace)
}

func (m *storeSim) fail(format string, args ...any) {
	m.mu.Lock()
	m.failures = append(m.failures, fmt.Sprintf(format, args...))
	m.mu.Unlock()
}

// --- падения ---

// point — точка записи на диск: взведённое падение снимает здесь диск.
func (m *storeSim) point(where string) {
	if m.rushing {
		return
	}
	if m.armed < 0 || m.snap != nil || (m.armRoots && !strings.HasPrefix(where, "корни:")) {
		m.sizes = m.appendSizes(m.cfg)
		return
	}
	if m.points < m.armed {
		m.points++
		m.sizes = m.appendSizes(m.cfg)
		return
	}
	m.snap, m.snapAt = m.snapshot(), where
	switch {
	case where == "цепь: head" && m.rng.IntN(2) == 0:
		m.tearHead()
	case m.rng.IntN(3) == 0:
		m.tear()
	}
	if m.rng.IntN(4) == 0 {
		m.litter()
	}
	if m.shipped && m.rng.IntN(25) == 0 {
		m.lie()
	}
}

// lie — врущий диск: в снимке пропадает то, что уже прошло fsync, — последние
// записи журнала улик или последнее звено цепи.
func (m *storeSim) lie() {
	evDir, chainDir, _ := dirs(m.snap)
	path, head := filepath.Join(chainDir, "chain.log"), 0
	if m.rng.IntN(2) == 0 {
		segs, _ := filepath.Glob(filepath.Join(evDir, "seg_*.log"))
		if len(segs) == 0 {
			return
		}
		path, head = segs[len(segs)-1], 16
	}
	offs := frameStarts(m.t, path, head, path != filepath.Join(chainDir, "chain.log"))
	if len(offs) == 0 {
		return
	}
	k := 1 + m.rng.IntN(min(len(offs), 3))
	if err := os.Truncate(path, offs[len(offs)-k]); err != nil {
		m.t.Fatal(err)
	}
	m.lostFsynced = true
	m.stats.lies++
	m.snapAt += fmt.Sprintf(", ВРУЩИЙ ДИСК: пропали %d последних кадров %s", k, filepath.Base(path))
}

// frameStarts — смещения целых кадров файла: журнала улик (длина, CRC, данные)
// или цепи (длина, данные, CRC).
func frameStarts(t *testing.T, path string, head int, evlogFrame bool) []int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []int64
	for off := head; off+8 <= len(data); {
		size := int(binary.BigEndian.Uint32(data[off:]))
		if off+8+size > len(data) {
			break
		}
		out = append(out, int64(off))
		off += 8 + size
	}
	_ = evlogFrame // у обоих видов кадра служебные 8 байт: длина впереди
	return out
}

// simRemote — копия наружу с точкой падения перед каждым куском.
type simRemote struct {
	ship.Remote
	m *storeSim
}

func (r simRemote) Put(ctx context.Context, key string, data []byte) error {
	r.m.point("копия: перед куском")
	if r.m.snap != nil {
		// Процесс уже упал: умерший экземпляр доигрывает операцию в своих
		// каталогах, но наружу от него не уходит ничего — иначе прерванная
		// отправка копии не оставалась бы в копии никогда.
		return errSimDead
	}
	return r.Remote.Put(ctx, key, data)
}

var errSimDead = errors.New("симуляция: процесс уже упал")

// tearHead — отказ посреди записи головы цепи: слот, который пишется (звено
// уже на диске), в снимке испорчен.
func (m *storeSim) tearHead() {
	_, chainDir, _ := dirs(m.snap)
	links, err := auditchain.ReadChain(chainDir)
	if err != nil {
		m.t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(chainDir, "chain.head"), os.O_WRONLY, 0)
	if err != nil {
		m.t.Fatal(err)
	}
	defer f.Close()
	junk := make([]byte, 20)
	for i := range junk {
		junk[i] = byte(m.rng.IntN(256))
	}
	if _, err := f.WriteAt(junk, int64(len(links)%2)*48); err != nil {
		m.t.Fatal(err)
	}
	m.snapAt += ", посреди записи головы цепи"
	m.stats.headTears++
}

// litter — недописанные временные файлы в снимке: падение посреди атомарной
// записи (tmp → rename) оставляет их на диске.
func (m *storeSim) litter() {
	evDir, _, _ := dirs(m.snap)
	segs, _ := filepath.Glob(filepath.Join(evDir, "seg_*.log"))
	junk := []byte("недописано")
	var paths []string
	if len(segs) > 0 {
		last := segs[len(segs)-1]
		first, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(last), "seg_"), ".log"), 10, 64)
		paths = append(paths, filepath.Join(evDir, fmt.Sprintf("seg_%020d.log.tmp", first+uint64(evRecords(m.t, last)))))
	}
	paths = append(paths, filepath.Join(m.snap.DataDir, keyring.FileName+".tmp"), filepath.Join(m.snap.Keys.BackupDir, keyring.FileName+".tmp"))
	for _, p := range paths {
		if err := os.WriteFile(p, junk, 0o600); err != nil {
			m.t.Fatal(err)
		}
	}
	m.snapAt += ", с недописанными .tmp"
	m.stats.litter++
}

// evRecords — сколько целых записей в сегменте журнала улик.
func evRecords(t *testing.T, path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for off := 16; off+8 <= len(data); n++ { // заголовок сегмента — 16 байт
		size := int(binary.BigEndian.Uint32(data[off:]))
		if off+8+size > len(data) {
			break
		}
		off += 8 + size
	}
	return n
}

// appendSizes — размеры дописываемых файлов хранилища.
func (m *storeSim) appendSizes(cfg *config.Config) map[string]int64 {
	out := map[string]int64{}
	evDir, chainDir, _ := dirs(cfg)
	for _, pat := range []string{filepath.Join(evDir, "seg_*.log"), filepath.Join(chainDir, "leaves_*.log"), filepath.Join(chainDir, "chain.log")} {
		paths, _ := filepath.Glob(pat)
		for _, p := range paths {
			if fi, err := os.Stat(p); err == nil {
				rel, _ := filepath.Rel(cfg.DataDir, p)
				out[rel] = fi.Size()
			}
		}
	}
	return out
}

// tear — падение посреди записи: дописываемый файл, выросший с прошлой точки
// (один — иначе порядок fsync между ними неизвестен), в снимке обрывается
// посредине дописанного.
func (m *storeSim) tear() {
	now := m.appendSizes(m.cfg)
	var grown []string
	for rel, size := range now {
		if size > m.sizes[rel] {
			grown = append(grown, rel)
		}
	}
	if len(grown) != 1 {
		return
	}
	rel := grown[0]
	from := m.sizes[rel]
	if from == 0 && strings.HasPrefix(rel, "evidence") {
		from = 16 // новый сегмент журнала: заголовок пишется до данных и раньше переименования
	}
	cut := from + m.rng.Int64N(now[rel]-from)
	if err := os.Truncate(filepath.Join(m.snap.DataDir, rel), cut); err != nil {
		m.t.Fatal(err)
	}
	m.snapAt += fmt.Sprintf(", посреди записи %s (%d из %d байт)", rel, cut-from, now[rel]-from)
}

// newDir — путь нового каталога сценария (сам каталог создаст тот, кто
// пишет: Init или копия снимка).
func (m *storeSim) newDir(name string) string {
	d, err := os.MkdirTemp(m.root, name+"-")
	if err != nil {
		m.t.Fatal(err)
	}
	return filepath.Join(d, name)
}

// dropDirs удаляет каталоги умершего процесса: снимков за сценарий — сотни.
func (m *storeSim) dropDirs(cfg *config.Config) {
	for _, d := range []string{cfg.DataDir, cfg.RootsDir, cfg.Keys.BackupDir} {
		os.RemoveAll(filepath.Dir(d))
	}
}

// snapshot — копия диска хранилища: так его оставит упавший процесс.
func (m *storeSim) snapshot() *config.Config {
	out := *m.cfg
	out.DataDir = m.newDir("data")
	out.RootsDir = m.newDir("roots")
	out.Keys.BackupDir = m.newDir("backup")
	out.AdminSocket = filepath.Join(out.DataDir, "admin.sock")
	for src, dst := range map[string]string{m.cfg.DataDir: out.DataDir, m.cfg.RootsDir: out.RootsDir, m.cfg.Keys.BackupDir: out.Keys.BackupDir} {
		if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
			m.t.Fatal(err)
		}
	}
	return &out
}

// op — операция процесса хранилища. countEnd — конец операции тоже точка
// падения: ответ клиенту ещё не ушёл. Упали посреди или в конце — crashed:
// результата нет, хранилище поднято из снимка.
func (m *storeSim) op(name string, countEnd bool, fn func() error) (err error, crashed bool) {
	err = fn()
	if countEnd {
		m.point("конец: " + name)
	}
	if m.snap == nil {
		return err, false
	}
	m.crash()
	return nil, true
}

func (m *storeSim) countCrash(at string) {
	m.stats.crashes++
	if strings.HasPrefix(at, "корни:") {
		m.stats.rootCrashes++
	}
	if strings.Contains(at, "посреди записи") {
		m.stats.torn++
	}
}

// crash — процесс упал: прежний экземпляр брошен, хранилище поднимается из
// снимка.
func (m *storeSim) crash() {
	snap, at := m.snap, m.snapAt
	m.snap, m.armed, m.points, m.armRoots = nil, -1, 0, false
	if m.s != nil {
		m.s.chain.SetBeforeWrite(nil)
		m.s.Close() // пишет только в каталоги умершего процесса
		m.s = nil
	}
	locked := m.backupLocked
	m.unlockBackup() // каталоги умершего процесса — удалимы
	m.dropDirs(m.cfg)
	m.cfg = snap
	if locked {
		m.lockBackupDir() // недоступный диск недоступен и после падения
	}
	m.note("ПАДЕНИЕ: %s; подъём из снимка", at)
	m.countCrash(at)
	dirty := m.rushDirty
	m.rushDirty = false
	m.open()
	if m.s != nil && (dirty || strings.Contains(at, "посреди записи chain/leaves_")) {
		m.markLostGaps()
	}
	// Связанный отказ: машина умерла посреди прохода копии, и диск её не
	// пережил — в копии прерванный проход, подъём — из неё.
	if m.s != nil && strings.HasPrefix(at, "копия:") && m.shipped && m.rng.IntN(3) == 0 {
		m.stats.copyDeaths++
		m.disasterRestore()
	}
}

// markLostGaps — предел README: обрыв записи листьев цепи, падение после
// тика звена, сбросившего улики раньше событий о пропуске (тик шёл вместе с
// приёмом), или обрезка цепи по голове при подъёме из копии унесли событие о
// пропуске, а улика со следующим номером уцелела (в цепи; в журнале улик,
// откуда подъём досчитал её в цепь); после подъёма событие объявляется
// только выше последнего номера в цепи. Пропущенные номера ниже принятого максимума без
// события в цепи — потерянные события.
func (m *storeSim) markLostGaps() {
	gaps := m.chainGaps()
	for _, c := range m.clients {
		last, _ := m.s.LastSeq(c.source)
		// Пропущенные сборщиком и потерянные вместе с диском — одинаково.
		missing := slices.Collect(maps.Keys(c.skipped))
		m.s.mu.Lock()
		for q := range c.drLost {
			if m.s.sources[c.source].seqs.get(q) == 0 {
				missing = append(missing, q)
			}
		}
		m.s.mu.Unlock()
		for _, q := range missing {
			if q < last && !c.gapLost[q] && !covered(gaps[c.source], q) {
				c.gapLost[q] = true
				m.note("%s/%d: событие пропуска пропало с хвостом цепи (предел README)", c.source, q)
			}
		}
	}
}

// chainGaps — события пропуска в цепи на диске, по источникам.
func (m *storeSim) chainGaps() map[string][][2]uint64 {
	_, chainDir, _ := dirs(m.cfg)
	gaps := map[string][][2]uint64{}
	err := auditchain.ScanLeaves(chainDir, func(_ uint64, l auditchain.Leaf) error {
		if l.Type == auditchain.EventGap {
			var g gap
			if err := json.Unmarshal(l.Payload, &g); err != nil {
				return err
			}
			gaps[l.Scope] = append(gaps[l.Scope], [2]uint64{g.From, g.To})
		}
		return nil
	})
	if err != nil {
		m.fail("цепь: %v", err)
	}
	return gaps
}

func covered(gaps [][2]uint64, q uint64) bool {
	return slices.ContainsFunc(gaps, func(g [2]uint64) bool { return g[0] <= q && q <= g[1] })
}

// open поднимает хранилище, как serve: приём закрыт до свежей метки, первая
// метка — сразу.
func (m *storeSim) open() {
	var s *Store
	err, crashed := m.op("подъём", false, func() error {
		var err error
		s, err = Open(m.cfg, m.options(m.point))
		return err
	})
	if crashed {
		if s != nil {
			s.Close()
		}
		return
	}
	if err != nil {
		if m.lostFsynced && loudLoss(err) {
			m.stats.loud++
			m.note("хранилище отказало громко: %v", err)
			m.disasterRestore()
			return
		}
		m.fail("не поднялось после падения: %v", err)
		return
	}
	s.needAnchor = true
	s.chain.SetBeforeWrite(func(phase string) error { m.point("цепь: " + phase); return nil })
	m.s = s
	m.pub, _ = base64.RawStdEncoding.DecodeString(s.PublicKey())
	now := m.clk.now()
	m.lastAnchor, m.lastMaintain, m.lastStamp = now, now, now
	m.note("хранилище поднято")
	if m.lostFsynced {
		m.markDiskLost()
	}
	if m.gapsAfterOpen {
		m.gapsAfterOpen = false
		m.markLostGaps()
	}
	if orphans, err := s.keys.OrphanRoots(); err == nil && len(orphans) > 0 {
		m.stats.orphansSeen++
		m.note("корни-сироты: %v", orphans)
	}
	m.stamp("метка при запуске", false)
}

// options — настройки подъёма хранилища в симуляции.
func (m *storeSim) options(hook func(string)) Options {
	opt := Options{Logger: m.logger, Now: m.clk.now, NoBackground: true, writeHook: hook,
		evlogSegment: m.evSeg, chainSegment: m.chainSeg, replicaChunk: m.repChunk}
	if hook != nil {
		opt.wrapRoots = func(rs keyring.RootStore) keyring.RootStore { return simRoots{rs, m} }
	}
	return opt
}

// simRoots — хранилище корней с точками падения посреди поворота корня:
// новый корень заведён, а keyring.dat ещё под старым; старый корень вот-вот
// уничтожен или уже нет.
type simRoots struct {
	keyring.RootStore
	m *storeSim
}

func (r simRoots) NewRoot() (string, error) {
	r.m.point("корни: перед новым корнем")
	id, err := r.RootStore.NewRoot()
	if err == nil {
		r.m.point("корни: новый корень заведён")
	}
	return id, err
}

func (r simRoots) DestroyRoot(id string) error {
	r.m.point("корни: перед уничтожением корня")
	err := r.RootStore.DestroyRoot(id)
	if err == nil {
		r.m.point("корни: корень уничтожен")
	}
	return err
}

// loudLoss — отказ, которым хранилище говорит о потере подтверждённого.
func loudLoss(err error) bool {
	return errors.Is(err, ErrEvidenceLost) || errors.Is(err, auditchain.ErrTruncatedChain) ||
		errors.Is(err, auditchain.ErrLeavesMissing) || errors.Is(err, evlog.ErrCorrupt)
}

// markDiskLost — принятые записи, которых нет после подъёма из копии или
// после врущего диска: потеряны вместе с диском.
func (m *storeSim) markDiskLost() {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	for _, c := range m.clients {
		st := m.s.sources[c.source]
		n := 0
		for q := range c.acked {
			if !c.drLost[q] && st.seqs.get(q) == 0 {
				c.drLost[q] = true
				n++
			}
		}
		if n > 0 {
			m.stats.drLost += n
			m.note("%s: %d принятых потеряно вместе с диском", c.source, n)
		}
	}
}

// disasterRestore — диск data_dir потерян (или хранилище громко отказало):
// оператор собирает журнал и цепь из копии наружу, keyring.dat и sign.key
// кладёт из резерва ключей. Принятое после последней копии потеряно.
func (m *storeSim) disasterRestore() {
	if m.s != nil {
		m.s.chain.SetBeforeWrite(nil)
		m.s.Close()
		m.s = nil
	}
	old := m.cfg
	nc := *old
	nc.DataDir = m.newDir("data")
	nc.AdminSocket = filepath.Join(nc.DataDir, "admin.sock")
	if _, err := RestoreReplica(context.Background(), m.remoteRaw, nc.DataDir, m.pub); err != nil {
		m.fail("подъём из копии наружу: %v", err)
		return
	}
	for name, dst := range map[string]string{
		keyring.FileName:           filepath.Join(nc.DataDir, keyring.FileName),
		auditchain.SignKeyFileName: filepath.Join(nc.DataDir, "chain", auditchain.SignKeyFileName),
	} {
		data, err := os.ReadFile(filepath.Join(nc.Keys.BackupDir, name))
		if err != nil {
			m.t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			m.t.Fatal(err)
		}
	}
	_, _, oldTSA := dirs(old)
	_, _, newTSA := dirs(&nc)
	if err := os.CopyFS(newTSA, os.DirFS(oldTSA)); err != nil { // демо-TSA живёт в data_dir; настоящая — снаружи
		m.t.Fatal(err)
	}
	os.RemoveAll(filepath.Dir(old.DataDir)) // потерянный диск
	m.cfg = &nc
	m.lostFsynced, m.diverged = false, false
	m.stats.drs++
	m.restoredAt = append(m.restoredAt, m.clk.now())
	m.note("ДИСК ПОТЕРЯН: подъём из копии наружу и резерва ключей")
	m.open()
	if m.s != nil {
		lostBefore := map[*simClient]map[uint64]bool{}
		for _, c := range m.clients {
			lostBefore[c] = maps.Clone(c.drLost)
		}
		m.markDiskLost()
		// Всё, что было принято до начала последнего прохода копии, дошедшего
		// до подписанной головы, обязано подняться из копии (то, что раньше
		// потерял врущий диск, уже отмечено потерянным).
		for _, c := range m.clients {
			for q := range c.drLost {
				if !lostBefore[c][q] && c.ackedAt[q] <= m.copied {
					m.fail("принятая %s/%d уехала в копию полным проходом (ответ №%d, копия накрывает до №%d), а из копии не поднялась",
						c.source, q, c.ackedAt[q], m.copied)
				}
			}
		}
		m.copied = m.acks.Load() // поднятое — ровно то, что в копии
		m.markLostGaps()
		for _, c := range m.clients {
			c.bound = false // закрепление после последней копии могло пропасть
		}
	}
}

// newCopyLocation — оператор оставляет data_dir, а копию переводит на новое
// место (replica.url меняется с перезапуском); прежняя копия остаётся как
// была. Подниматься не из чего, пока на новом месте нет подписанной головы.
func (m *storeSim) newCopyLocation() {
	dir := m.newDir("remote")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		m.t.Fatal(err)
	}
	m.cfg.Replica.URL = "file://" + dir
	raw, err := ship.OpenRemote(m.cfg.Replica.URL)
	if err != nil {
		m.t.Fatal(err)
	}
	m.remoteRaw, m.remote = raw, simRemote{raw, m}
	m.shipped, m.lostFsynced, m.diverged, m.copied = false, false, false, 0
	m.stats.relocations++
	m.note("копия переведена на новое место")
	m.restart()
}

// diskLost — шаг оператора: диск data_dir потерян.
func (m *storeSim) diskLost() {
	if !m.shipped {
		return
	}
	m.disasterRestore()
}

// arm взводит падение на одной из ближайших точек записи.
func (m *storeSim) arm() {
	if m.armed >= 0 {
		return
	}
	m.armed, m.points = m.rng.IntN(6), 0
	if slices.ContainsFunc(m.s.Keys(), func(ki keyring.KeyInfo) bool { return ki.State == keyring.Pending }) && m.rng.IntN(2) == 0 {
		m.armed, m.armRoots = m.rng.IntN(4), true
		m.note("падение взведено: точка поворота корня %d", m.armed)
		return
	}
	m.note("падение взведено: точка %d", m.armed)
}

// crashBetween — падение между операциями.
func (m *storeSim) crashBetween() {
	m.armed, m.points, m.armRoots = 0, 0, false
	m.point("между операциями")
	m.crash()
}

func (m *storeSim) restart() {
	m.s.chain.SetBeforeWrite(nil)
	if err := m.s.Close(); err != nil {
		m.fail("остановка: %v", err)
		return
	}
	m.s = nil
	m.rushDirty = false // Close сбрасывает звено
	m.stats.restarts++
	m.note("штатная остановка")
	if m.rng.IntN(2) == 0 {
		m.saveKeyring()
	}
	m.open()
}

// saveKeyring запоминает нынешний keyring.dat: им потом делается откат и по
// нему проверяется, что уничтоженный ключ не воскресает.
func (m *storeSim) saveKeyring() {
	if len(m.oldKeyrings) >= 12 {
		m.oldKeyrings = slices.Delete(m.oldKeyrings, 1, 2) // первая копия (до всего) остаётся
	}
	m.oldKeyrings = append(m.oldKeyrings, m.readKeyring())
}

// --- работа оператора и отказы диска ---

func (m *storeSim) readKeyring() []byte {
	data, err := os.ReadFile(filepath.Join(m.cfg.DataDir, keyring.FileName))
	if err != nil {
		m.t.Fatal(err)
	}
	return data
}

// stopStore — процесс остановлен (штатно или упал: crash).
func (m *storeSim) stopStore(crash bool) {
	if crash {
		m.armed, m.points, m.armRoots = 0, 0, false
		m.point("между операциями")
		m.countCrash(m.snapAt)
		m.note("ПАДЕНИЕ: %s (перед работой оператора); подъём из снимка", m.snapAt)
		snap := m.snap
		m.snap, m.armed, m.points = nil, -1, 0
		m.gapsAfterOpen, m.rushDirty = m.rushDirty, false
		m.s.chain.SetBeforeWrite(nil)
		m.s.Close()
		locked := m.backupLocked
		m.unlockBackup()
		m.dropDirs(m.cfg)
		m.cfg = snap
		if locked {
			m.lockBackupDir()
		}
	} else {
		m.s.chain.SetBeforeWrite(nil)
		if err := m.s.Close(); err != nil {
			m.fail("остановка: %v", err)
		}
		m.rushDirty = false // Close сбрасывает звено
	}
	m.s = nil
}

// restoreKeyring — keyring.dat потерян или испорчен (процесс упал или
// остановлен), оператор поднимает его из резерва, как велит README:
// хранилище обязано подняться — резерв не бывает позади квитанций в цепи.
func (m *storeSim) restoreKeyring() {
	m.stopStore(m.rng.IntN(2) == 0)
	m.copyKeyringFromBackup()
	m.stats.restores++
	m.note("keyring.dat поднят из резерва")
	m.open()
}

func (m *storeSim) copyKeyringFromBackup() {
	data, err := os.ReadFile(filepath.Join(m.cfg.Keys.BackupDir, keyring.FileName))
	if err != nil {
		m.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.cfg.DataDir, keyring.FileName), data, 0o600); err != nil {
		m.t.Fatal(err)
	}
}

// rollbackKeyring — по ошибке подложена старая копия keyring.dat: хранилище
// либо отказывает (она позади цепи), либо поднимается с ней; резерв при
// этом не затёрт — подъём из резерва после этого обязан пройти.
func (m *storeSim) rollbackKeyring() {
	m.stopStore(false)
	old := m.oldKeyrings[m.rng.IntN(len(m.oldKeyrings))]
	if err := os.WriteFile(filepath.Join(m.cfg.DataDir, keyring.FileName), old, 0o600); err != nil {
		m.t.Fatal(err)
	}
	m.stats.rollbacks++
	s, err := Open(m.cfg, m.options(nil))
	switch {
	case err == nil:
		s.Close()
		m.note("откат keyring.dat: хранилище поднялось со старой копией")
	case errors.Is(err, ErrKeyringMismatch):
		m.note("откат keyring.dat: отказ (старая копия позади цепи)")
	case errors.Is(err, os.ErrNotExist):
		m.note("откат keyring.dat: отказ (корень старой копии уничтожен)")
	default:
		m.fail("откат keyring.dat: %v", err)
		return
	}
	m.copyKeyringFromBackup()
	m.note("keyring.dat поднят из резерва после отката")
	m.open()
}

// lockBackup — резерв ключей на время недоступен (права, отвалившийся диск):
// копии keyring.dat не проходят, новый ключ не выдаётся, квитанции ждут.
func (m *storeSim) lockBackup() {
	if m.backupLocked {
		return
	}
	m.lockBackupDir()
	ds := []time.Duration{20 * time.Second, 2 * time.Minute, 10 * time.Minute}
	m.backupFixAt = m.clk.now().Add(ds[m.rng.IntN(len(ds))])
	m.note("резерв ключей недоступен до %s", m.backupFixAt.Format("15:04:05"))
}

func (m *storeSim) lockBackupDir() {
	if err := os.Chmod(m.cfg.Keys.BackupDir, 0o500); err != nil {
		m.t.Fatal(err)
	}
	m.backupLocked = true
}

func (m *storeSim) unlockBackup() {
	if m.backupLocked {
		os.Chmod(m.cfg.Keys.BackupDir, 0o700)
		m.backupLocked = false
	}
}

// keyOperator — работа с ключами: заявка двух людей на уничтожение закрытого
// месяца (только когда сборщикам нечего дослать: в жизни месяцы уничтожают
// через срок хранения, а повтор записи под ключом, ждущим уничтожения,
// законно получает отказ), отмена заявки, уничтожение корней-сирот.
func (m *storeSim) keyOperator() {
	var deactivated, pending []string
	for _, ki := range m.s.Keys() {
		switch ki.State {
		case keyring.Deactivated:
			deactivated = append(deactivated, ki.Scope)
		case keyring.Pending:
			pending = append(pending, ki.Scope)
		}
	}
	unacked := slices.ContainsFunc(m.clients, func(c *simClient) bool { return len(c.unacked) > 0 })
	orphans, _ := m.s.keys.OrphanRoots()
	switch {
	case len(orphans) > 0 && m.rng.IntN(2) == 0:
		err, crashed := m.op("уничтожение сирот", true, func() error { _, err := m.s.DestroyOrphanRoots(); return err })
		m.keyOpResult("корни-сироты уничтожены", err, crashed)
	case len(pending) > 0 && m.rng.IntN(4) == 0:
		sc := pending[m.rng.IntN(len(pending))]
		m.saveKeyring()
		err, crashed := m.op("отмена уничтожения "+sc, true, func() error {
			_, err := m.s.CancelDestroy(sc, []keyring.Approval{{Who: "carol"}})
			return err
		})
		m.keyOpResult("отмена уничтожения "+sc, err, crashed)
	case len(deactivated) > 0 && m.rng.IntN(5) == 0:
		// Ошибка оператора: заявку подаёт один человек дважды — отказ.
		sc := deactivated[m.rng.IntN(len(deactivated))]
		err, crashed := m.op("заявка одного человека "+sc, false, func() error {
			_, err := m.s.ScheduleDestroy(context.Background(), sc, time.Minute, []keyring.Approval{{Who: "alice"}, {Who: "alice"}})
			return err
		})
		if !crashed && err == nil {
			m.fail("заявке на уничтожение %s хватило одного человека", sc)
		}
	case len(deactivated) > 0 && !unacked:
		sc := deactivated[m.rng.IntN(len(deactivated))]
		wait := []time.Duration{time.Minute, 3 * time.Minute}[m.rng.IntN(2)]
		m.saveKeyring()
		err, crashed := m.op("заявка на уничтожение "+sc, true, func() error {
			_, err := m.s.ScheduleDestroy(context.Background(), sc, wait, []keyring.Approval{{Who: "alice"}, {Who: "bob"}})
			return err
		})
		m.keyOpResult(fmt.Sprintf("заявка на уничтожение %s через %s", sc, wait), err, crashed)
		if !crashed && err == nil {
			m.checkErased(sc)
		}
	}
}

// checkErased — ключ месяца ждёт уничтожения: тело записи этого месяца не
// выдаётся (пакет доказывает только существование и неизменность).
func (m *storeSim) checkErased(scope string) {
	for _, c := range m.clients {
		for q, sc := range c.scope {
			if sc != scope || c.drLost[q] {
				continue
			}
			b, err := m.s.Proof(c.source, q, true)
			switch {
			case err != nil:
				m.fail("пакет %s/%d после заявки на уничтожение: %v", c.source, q, err)
			case len(b.DEK) > 0:
				m.fail("%s/%d: ключ %s ждёт уничтожения, а ключ записи выдан", c.source, q, scope)
			}
			return
		}
	}
}

func (m *storeSim) keyOpResult(what string, err error, crashed bool) {
	switch {
	case crashed:
	case err == nil:
		switch {
		case strings.HasPrefix(what, "заявка"):
			m.stats.schedules++
		case strings.HasPrefix(what, "отмена"):
			m.stats.cancels++
		default:
			m.stats.orphanRuns++
		}
		m.note("%s", what)
	case errors.Is(err, keyring.ErrBackupPending) && m.backupLocked:
		m.note("%s; копия в резерв ждёт", what)
	default:
		m.fail("%s: %v", what, err)
	}
}

// bodyReadable — тело записи под ключом скоупа ещё можно вскрыть: повтор
// такой записи сверяется по телу.
func (m *storeSim) bodyReadable(scope string) bool {
	ki, ok := m.s.keyInfo(scope)
	return ok && (ki.State == keyring.Active || ki.State == keyring.Deactivated)
}

// rogueContact — чужая установка сборщика с тем же сертификатом: после того
// как хранилище закрепило источник за честной, ей — отказ.
func (m *storeSim) rogueContact(c *simClient) {
	if !c.bound {
		return
	}
	err, crashed := m.op("чужая установка "+c.source, false, func() error { return m.s.Admit(c.source, c.rogue) })
	if !crashed && !errors.Is(err, ErrEpochMismatch) {
		m.fail("чужая установка %s принята: %v", c.source, err)
	}
}

// --- время и фоновые циклы ---

func (m *storeSim) step() {
	c := m.clients[m.rng.IntN(len(m.clients))]
	r := m.rng.IntN(100)
	if m.calm && (r >= 70 && r < 91 || r >= 95 && r < 96) {
		r = 50 // спокойный сценарий: вместо падений и работы оператора — время
	}
	switch {
	case r < 45:
		m.ingest(c, true)
	case r < 52:
		m.rush()
	case r < 55:
		m.ship()
	case r < 70:
		ds := []time.Duration{200 * time.Millisecond, time.Second, 3 * time.Second, 10 * time.Second, 40 * time.Second}
		m.advance(ds[m.rng.IntN(len(ds))])
	case r < 77:
		m.arm()
	case r < 80:
		m.crashBetween()
	case r < 83:
		m.restart()
	case r < 86:
		m.stamp("метка оператора", true)
	case r < 88:
		m.restoreKeyring()
	case r < 89:
		m.rollbackKeyring()
	case r < 91:
		m.lockBackup()
	case r < 93:
		m.rogueContact(c)
	case r < 95:
		m.keyOperator()
	case r < 96:
		m.diskLost()
	default:
		ds := []time.Duration{5 * time.Minute, 20 * time.Minute, time.Hour}
		m.advance(ds[m.rng.IntN(len(ds))])
	}
}

// rush — параллельная работа, как в serve: каждый клиент шлёт пачки из своей
// горутины, фоновые циклы (звено, молчание и якорь, обслуживание, метка,
// копия) идут из своей, и время идёт. Падений и работы оператора здесь нет:
// снимок диска посреди чужих записей — состояние, какого у настоящего диска
// не бывает. Гонки ловят эталон в конце сценария и -race; порядок горутин
// случаен, поэтому STORESIM_SEED повторяет такой сценарий не байт в байт.
func (m *storeSim) rush() {
	// Снимок, снятый в шаге оператора без op (перезапуск закрывает
	// хранилище, и ключи пишутся), — падение, которое ещё не случилось:
	// сначала оно, по порядку. Иначе его сыграл бы первый же приём из
	// горутины клиента, закрыв хранилище под ногами фоновых циклов.
	if m.snap != nil {
		m.crash()
	}
	if m.s == nil {
		return
	}
	m.armed, m.points, m.armRoots = -1, 0, false
	m.rushing = true
	m.stats.rushes++
	var wg sync.WaitGroup
	var twins, rogues atomic.Int64
	for _, c := range m.clients {
		c.rng = mrand.New(mrand.NewPCG(m.rng.Uint64(), m.rng.Uint64()))
		n := 2 + m.rng.IntN(8)
		m.stats.rushBatches += n
		wg.Go(func() {
			for range n {
				if c.rng.IntN(4) == 0 {
					twins.Add(1)
					m.ingestTwice(c)
				} else {
					m.ingest(c, true)
				}
				runtime.Gosched()
			}
		})
		if c.bound && m.rng.IntN(4) == 0 {
			rogues.Add(1)
			wg.Go(func() {
				for range 3 {
					if err := m.s.Admit(c.source, c.rogue); !errors.Is(err, ErrEpochMismatch) {
						m.fail("чужая установка %s во время приёма: %v", c.source, err)
					}
					runtime.Gosched()
				}
			})
		}
	}
	ticks := 3 + m.rng.IntN(30)
	m.note("параллельная работа: %d с", ticks)
	wg.Go(func() {
		for range ticks {
			m.clk.add(time.Second)
			m.rushBackground()
			runtime.Gosched()
		}
	})
	wg.Wait()
	m.stats.twins += int(twins.Load())
	m.stats.rogueRaces += int(rogues.Load())
	for _, c := range m.clients {
		c.rng = nil
	}
	m.rushing, m.rushDirty = false, true
	m.sizes = m.appendSizes(m.cfg)
}

// ingestTwice — сборщик не дождался ответа и послал ту же пачку снова, пока
// первая ещё в работе: два одинаковых запроса идут одновременно. Ответы
// обязаны сойтись: у номера одно обещание байт в байт и не больше одного
// «принято»; или один из запросов получает ErrInFlight (номер пишет другой).
func (m *storeSim) ingestTwice(c *simClient) {
	recs := m.batch(c, true)
	if len(recs) == 0 {
		return
	}
	var res [2][]Result
	var errs [2]error
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Go(func() {
			if errs[i] = m.s.Admit(c.source, c.epoch); errs[i] == nil {
				res[i], errs[i] = m.s.Ingest(c.source, recs)
			}
		})
	}
	wg.Wait()
	var ok [][]Result
	for i := range 2 {
		switch err := errs[i]; {
		case err == nil:
			c.bound = true
			ok = append(ok, res[i])
		case errors.Is(err, ErrInFlight): // тот же номер пишет второй запрос: сборщик повторит позже
		case errors.Is(err, ErrNoAnchor):
		case (errors.Is(err, keyring.ErrNotBackedUp) || errors.Is(err, keyring.ErrBackupPending)) && m.backupLocked:
		default:
			m.fail("приём %s (два запроса сразу): %v", c.source, err)
			return
		}
	}
	if len(ok) == 0 {
		return
	}
	if len(ok) == 2 && len(ok[0]) == len(recs) && len(ok[1]) == len(recs) {
		for k, a := range ok[0] {
			b := ok[1][k]
			if a.Promise == nil || b.Promise == nil || !samePromise(*a.Promise, *b.Promise) ||
				a.Status == StatusAccepted && b.Status == StatusAccepted {
				m.fail("%s/%d двумя запросами сразу: %s и %s, обещания %+v и %+v", c.source, recs[k].Seq, a.Status, b.Status, a.Promise, b.Promise)
				return
			}
		}
	}
	m.deliver(c, recs, ok[0])
	m.note("%s: принято до %d (пачка %d, двумя запросами сразу)", c.source, recs[len(recs)-1].Seq, len(recs))
}

// rushBackground — фоновые циклы в параллельной работе: без работы
// оператора, отказ копии ждёт его до конца захода.
func (m *storeSim) rushBackground() {
	now := m.clk.now()
	if err := m.s.flush(); err != nil {
		m.fail("звено: %v", err)
	}
	if now.Sub(m.lastAnchor) >= anchorRetry {
		m.lastAnchor = now
		m.s.CheckSilence(now)
		if m.s.anchorStale() {
			if _, err := m.s.stampNow(context.Background()); err != nil {
				m.fail("якорь: %v", err)
			}
		}
	}
	if now.Sub(m.lastMaintain) >= time.Minute {
		m.lastMaintain = now
		m.s.Maintain(now)
	}
	if now.Sub(m.lastStamp) >= m.cfg.TSA.Every.D() {
		m.lastStamp = now
		if _, err := m.s.Stamp(context.Background()); err != nil {
			m.fail("метка: %v", err)
		}
	}
	if now.Sub(m.lastShip) >= m.cfg.Replica.Every.D() {
		m.lastShip = now
		before := m.acks.Load()
		_, err := m.s.ShipOnce(context.Background(), m.remote)
		switch {
		case err == nil && m.diverged:
			m.fail("копия, которую data_dir не продолжает, снова принимает куски")
		case err == nil:
			m.shipped, m.copied = true, max(m.copied, before)
		case m.lostFsynced && errors.Is(err, ErrReplicaDiverged):
			if !m.diverged {
				m.diverged = true
				m.stats.loud++
				m.stats.divergedCopies++
				m.note("копия отказала громко: %v", err)
			}
		default:
			m.fail("копия наружу: %v", err)
		}
	}
}

// advance — проходит время; фоновые циклы — по их расписанию.
func (m *storeSim) advance(d time.Duration) {
	end := m.clk.now().Add(d)
	for len(m.failures) == 0 && m.s != nil && m.clk.now().Before(end) {
		m.clk.add(min(time.Second, end.Sub(m.clk.now())))
		m.background()
	}
}

func (m *storeSim) background() {
	now := m.clk.now()
	if m.backupLocked && !now.Before(m.backupFixAt) {
		m.unlockBackup()
		m.note("резерв ключей снова доступен")
	}
	if !m.lockAt.IsZero() && !now.Before(m.lockAt) {
		m.lockAt = time.Time{}
		if !m.backupLocked {
			m.lockBackupDir()
			m.backupFixAt = m.lockUntil
			m.note("резерв ключей недоступен на смене ключа, до %s", m.lockUntil.Format("15:04:05"))
		}
	}
	if !m.restoreAt.IsZero() && !now.Before(m.restoreAt) {
		m.restoreAt = time.Time{}
		m.restoreKeyring()
		if m.s == nil {
			return
		}
	}
	if err, crashed := m.op("звено", false, m.s.flush); err != nil && !crashed {
		m.fail("звено: %v", err)
	} else if !crashed {
		m.rushDirty = false
	}
	if m.s == nil {
		return
	}
	if now.Sub(m.lastAnchor) >= anchorRetry {
		m.lastAnchor = now
		m.op("молчание", false, func() error { m.s.CheckSilence(now); return nil })
		if m.s != nil && m.s.anchorStale() {
			if err, crashed := m.op("якорь", true, func() error { _, err := m.s.stampNow(context.Background()); return err }); err != nil && !crashed {
				m.fail("якорь: %v", err)
			}
		}
	}
	if m.s != nil && now.Sub(m.lastMaintain) >= time.Minute {
		m.lastMaintain = now
		m.op("обслуживание", false, func() error { m.s.Maintain(now); return nil })
	}
	if m.s != nil && now.Sub(m.lastStamp) >= m.cfg.TSA.Every.D() {
		m.lastStamp = now
		m.stamp("метка", true)
	}
	if m.s != nil && now.Sub(m.lastShip) >= m.cfg.Replica.Every.D() {
		m.lastShip = now
		m.ship()
	}
}

// ship — проход копии наружу. В serve его таймер не связан с таймером звена,
// поэтому шаг сценария зовёт его и между звеньями: в копию уезжают улики, ещё
// не легшие в цепь, — их потом может потерять врущий диск.
func (m *storeSim) ship() {
	before := m.acks.Load()
	err, crashed := m.op("копия наружу", false, func() error { _, err := m.s.ShipOnce(context.Background(), m.remote); return err })
	switch {
	case crashed:
	case err == nil && m.diverged:
		m.fail("копия, которую data_dir не продолжает, снова принимает куски")
	case err == nil:
		m.shipped, m.copied = true, max(m.copied, before)
	case m.lostFsynced && errors.Is(err, ErrReplicaDiverged):
		if !m.diverged {
			m.diverged = true
			m.stats.loud++
			m.stats.divergedCopies++
			m.note("копия отказала громко: %v", err)
		}
		// Оператор приходит не сразу, а пока его нет, копия отказывает.
		switch m.rng.IntN(3) {
		case 0:
			m.disasterRestore()
		case 1:
			m.newCopyLocation()
		}
	default:
		m.fail("копия наружу: %v", err)
	}
}

func (m *storeSim) stamp(name string, countEnd bool) {
	if err, crashed := m.op(name, countEnd, func() error { _, err := m.s.Stamp(context.Background()); return err }); err != nil && !crashed {
		m.fail("%s: %v", name, err)
	}
}

// --- клиент ---

// batch — пачка клиента: неподтверждённые записи снова и (fresh) новые —
// иногда после пропущенных номеров — и изредка принятая повтором.
func (m *storeSim) batch(c *simClient, fresh bool) []Incoming {
	rng := m.rng
	if c.rng != nil {
		rng = c.rng
	}
	seqs := slices.Clone(c.unacked[:min(len(c.unacked), 200)])
	if fresh {
		if c.lines == nil && rng.IntN(5) == 0 {
			for range 1 + rng.IntN(3) {
				c.skipped[c.next] = true
				c.skipAt[c.next] = m.traceLen()
				c.next++
			}
		}
		for range 1 + rng.IntN(4) {
			q := c.next
			switch {
			case c.lines == nil:
				c.bodies[q] = fmt.Sprintf("%s-%d-%s", c.source, q, strings.Repeat("x", rng.IntN(30)))
			case q <= uint64(len(c.lines)):
				c.bodies[q] = string(c.lines[q-1])
			default:
				continue // журнал гейтвея кончился
			}
			c.next++
			c.unacked = append(c.unacked, q)
			seqs = append(seqs, q)
		}
		if len(c.acked) > 0 && rng.IntN(6) == 0 {
			done := slices.Sorted(maps.Keys(c.acked))
			if q := done[rng.IntN(len(done))]; !slices.Contains(seqs, q) && !c.drLost[q] && m.bodyReadable(c.scope[q]) {
				seqs = append(seqs, q)
			}
		}
	}
	slices.Sort(seqs)
	recs := make([]Incoming, len(seqs))
	for i, q := range seqs {
		recs[i] = Incoming{Seq: q, Body: []byte(c.bodies[q])}
	}
	return recs
}

// ingest — клиент шлёт пачку, как сервер приёма: сверка эпохи, потом приём.
func (m *storeSim) ingest(c *simClient, fresh bool) {
	recs := m.batch(c, fresh)
	if len(recs) == 0 {
		return
	}
	var res []Result
	admitted := false
	err, crashed := m.op("приём "+c.source, true, func() error {
		if err := m.s.Admit(c.source, c.epoch); err != nil {
			return err
		}
		admitted = true
		var err error
		res, err = m.s.Ingest(c.source, recs)
		return err
	})
	if !crashed && admitted {
		c.bound = true
	}
	switch {
	case crashed:
		return // ответа нет: записи остаются неподтверждёнными
	case errors.Is(err, ErrNoAnchor):
		m.note("%s: приём ждёт метки", c.source)
		return
	case (errors.Is(err, keyring.ErrNotBackedUp) || errors.Is(err, keyring.ErrBackupPending)) && m.backupLocked:
		// Резерв недоступен: ключ месяца не выдаётся, пока копия не пройдёт, —
		// и после рестарта тоже, даже если в резерве он уже есть (Z-05).
		m.note("%s: ключ месяца ждёт копии в резерв", c.source)
		return
	case err != nil:
		m.fail("приём %s: %v", c.source, err)
		return
	}
	m.deliver(c, recs, res)
	m.note("%s: принято до %d (пачка %d)", c.source, recs[len(recs)-1].Seq, len(recs))
}

// deliver — клиент получил ответ: обещания проверены, повтор принятого
// получил то же обещание.
func (m *storeSim) deliver(c *simClient, recs []Incoming, res []Result) {
	if len(res) != len(recs) {
		m.fail("ответ: %d итогов на %d записей", len(res), len(recs))
		return
	}
	for i, r := range res {
		q := recs[i].Seq
		if r.Seq != q || r.Promise == nil || (r.Status != StatusAccepted && r.Status != StatusDuplicate) {
			m.fail("ответ %s/%d: %+v", c.source, q, r)
			continue
		}
		p := *r.Promise
		if err := proof.VerifyPromise(p, m.pub); err != nil || p.Source != c.source || p.Seq != q || p.Position != r.Position {
			m.fail("обещание %s/%d не сходится: %v (%+v)", c.source, q, err, p)
			continue
		}
		if old, ok := c.acked[q]; ok {
			if r.Status != StatusDuplicate || !samePromise(old, p) {
				m.fail("повтор принятой %s/%d: %s, позиция %d → %d, время %d → %d", c.source, q, r.Status, old.Position, p.Position, old.ReceivedAt, p.ReceivedAt)
			}
			continue
		}
		c.acked[q] = p
		c.ackedAt[q] = m.acks.Add(1)
		c.scope[q] = monthScope(c.source, time.Unix(0, p.ReceivedAt))
	}
	c.unacked = slices.DeleteFunc(c.unacked, func(q uint64) bool { _, ok := c.acked[q]; return ok })
}

func samePromise(a, b proof.Promise) bool {
	return a.Source == b.Source && a.Seq == b.Seq && a.Position == b.Position && bytes.Equal(a.Digest, b.Digest) &&
		a.ReceivedAt == b.ReceivedAt && a.Deadline == b.Deadline && a.PublicKey == b.PublicKey && bytes.Equal(a.Signature, b.Signature)
}

// quiesce — падений больше нет; клиенты досылают неподтверждённое,
// обслуживание дописывает квитанции, метка накрывает всё.
func (m *storeSim) quiesce() {
	m.armed, m.armRoots = -1, false
	m.unlockBackup()
	m.note("тишина")
	// Потеря с диском в хвосте нумерации видна, когда придёт следующая
	// строка: источник пишет дальше.
	for _, c := range m.clients {
		if last, err := m.s.LastSeq(c.source); err == nil && slices.ContainsFunc(slices.Collect(maps.Keys(c.drLost)), func(q uint64) bool { return q > last }) {
			m.ingest(c, true)
		}
		if m.s == nil || len(m.failures) > 0 {
			return
		}
	}
	for range 30 {
		pending := false
		for _, c := range m.clients {
			if len(c.unacked) > 0 && len(m.failures) == 0 && m.s != nil {
				pending = true
				m.ingest(c, false)
			}
		}
		if !pending || len(m.failures) > 0 || m.s == nil {
			break
		}
		m.advance(10 * time.Second)
	}
	for _, c := range m.clients {
		if len(c.unacked) > 0 {
			m.fail("клиент %s не дослал %d записей", c.source, len(c.unacked))
		}
	}
	if len(m.failures) > 0 || m.s == nil {
		return
	}
	// Заявки, поданные до тишины, доходят до конца: срок ожидания проходит,
	// оператор уничтожает корни-сироты, обслуживание — ключи.
	m.advance(4 * time.Minute)
	if m.s == nil {
		return
	}
	if orphans, err := m.s.keys.OrphanRoots(); err == nil && len(orphans) > 0 {
		if _, err := m.s.DestroyOrphanRoots(); err != nil {
			m.fail("корни-сироты: %v", err)
		}
	}
	m.op("обслуживание", false, func() error { m.s.Maintain(m.clk.now()); return nil })
	m.stamp("последняя метка", false)
}

// --- эталон ---

func (m *storeSim) check() {
	s := m.s
	trust := proof.Trust{StoreKey: m.pub, TSA: s.tsaTrust}
	gwKey, err := gateway.ParseKey(pipelockKey(m.t))
	if err != nil {
		m.t.Fatal(err)
	}
	trust.GatewayKey = gwKey
	for _, c := range m.clients {
		last, err := s.LastSeq(c.source)
		if err != nil {
			m.fail("LastSeq %s: %v", c.source, err)
			continue
		}
		for q := uint64(1); q <= max(last, c.next-1); q++ {
			m.checkRecord(c, q, trust)
		}
		// Закрепление, легшее в цепь после последней подписанной головы копии,
		// пропадает с диском (улики того же источника подъём досчитывает по
		// журналу, а события — нет): источник закрепится при следующем
		// обращении, а клиент после подъёма мог и не обращаться — журнал
		// гейтвея кончился.
		if st := s.sources[c.source]; st.epoch != c.epoch && (c.bound || st.epoch != "") {
			m.fail("эпоха %s: закреплена %q, а у клиента %q", c.source, st.epoch, c.epoch)
		}
	}
	// Журнал улик: каждый номер источника — один раз, каждая улика — лист.
	type key struct {
		source string
		seq    uint64
	}
	where := map[key]uint64{}
	var gwPos []uint64           // улики журнала гейтвея по порядку журнала
	gwSeq := map[uint64]uint64{} // позиция → номер
	for pos := uint64(1); pos < s.evlog.Next(); pos++ {
		data, err := s.evlog.Read(pos)
		if err != nil {
			m.fail("журнал улик, позиция %d: %v", pos, err)
			continue
		}
		sealed, err := evidence.Unmarshal(data)
		if err != nil {
			m.fail("журнал улик, позиция %d: %v", pos, err)
			continue
		}
		k := key{sealed.Source, sealed.Seq}
		if p0, dup := where[k]; dup {
			m.fail("%s/%d в журнале улик дважды: позиции %d и %d", k.source, k.seq, p0, pos)
		}
		where[k] = pos
		if st := s.sources[sealed.Source]; st != nil && st.gw != nil {
			gwPos = append(gwPos, pos)
			gwSeq[pos] = sealed.Seq
		}
		if pos > uint64(len(s.evLeaf)) || s.evLeaf[pos-1] == 0 {
			m.fail("улика на позиции %d (%s/%d) без листа в цепи", pos, k.source, k.seq)
		}
	}
	// Потерянные с диском, которые вернулись (подъём из копии, где они были).
	back := map[string]map[uint64]bool{}
	lastSeq := map[string]uint64{}
	s.mu.Lock()
	for _, c := range m.clients {
		back[c.source] = map[uint64]bool{}
		lastSeq[c.source] = s.sources[c.source].maxSeq
		for q := range c.drLost {
			if s.sources[c.source].seqs.get(q) != 0 {
				back[c.source][q] = true
			}
		}
	}
	s.mu.Unlock()
	keys := s.keys.List()
	for _, ki := range keys {
		switch {
		case ki.State == keyring.Pending && !ki.DestroyAfter.After(m.clk.now()):
			m.fail("срок уничтожения %s прошёл (%s), а ключ не уничтожен", ki.Scope, ki.DestroyAfter.Format("15:04:05"))
		case ki.State == keyring.Destroyed && ki.EffectiveAt.IsZero():
			m.fail("уничтожение %s не стало окончательным", ki.Scope)
		case ki.State == keyring.Destroyed:
			m.stats.destroyed++
			if ki.DestroyedAt.Before(ki.DestroyAfter) {
				m.fail("ключ %s уничтожен %s — раньше срока %s", ki.Scope, ki.DestroyedAt.Format("15:04:05"), ki.DestroyAfter.Format("15:04:05"))
			}
			if who := slices.Compact(slices.Sorted(slices.Values(ki.Approvals))); len(who) < 2 {
				m.fail("ключ %s уничтожен по заявке %v — меньше двух человек", ki.Scope, ki.Approvals)
			}
		}
	}
	s.Close()
	m.s = nil
	m.checkNoResurrection(keys)
	evDir, chainDirStats, _ := dirs(m.cfg)
	segs, _ := filepath.Glob(filepath.Join(evDir, "seg_*.log"))
	leafs, _ := filepath.Glob(filepath.Join(chainDirStats, "leaves_*.log"))
	m.stats.evSegments, m.stats.leafFiles = len(segs), len(leafs)

	// Цепь на диске: пропуски, молчание, квитанции ключей.
	_, chainDir, _ := dirs(m.cfg)
	gaps := map[string][][2]uint64{}
	lastKey := map[string]string{}
	silent := map[string]bool{}
	verdicts := map[uint64][]gateway.Verdict{}
	err = auditchain.ScanLeaves(chainDir, func(num uint64, l auditchain.Leaf) error {
		switch l.Type {
		case auditchain.EventGateway:
			pos, v, err := proof.ParseGatewayLeaf(l)
			if err != nil {
				return err
			}
			verdicts[pos] = append(verdicts[pos], v)
		case auditchain.EventGap:
			var g gap
			if err := json.Unmarshal(l.Payload, &g); err != nil {
				return err
			}
			gaps[l.Scope] = append(gaps[l.Scope], [2]uint64{g.From, g.To})
		case auditchain.EventKeyState:
			lastKey[l.Scope] = l.Subject
		case auditchain.EventSilence:
			if silent[l.Scope] {
				m.fail("«%s молчит» дважды за один эпизод (лист %d)", l.Scope, num)
			}
			silent[l.Scope] = true
		case auditchain.EventEvidence:
			silent[l.Scope] = false
		}
		return nil
	})
	if err != nil {
		m.fail("цепь: %v", err)
	}
	for _, c := range m.clients {
		for _, q := range slices.Sorted(maps.Keys(c.skipped)) {
			if !c.gapLost[q] && !covered(gaps[c.source], q) {
				at := c.skipAt[q]
				m.fail("номер %s/%d пропущен, а события пропуска в цепи нет (пропуски: %v)\nход от пропуска:\n  %s", c.source, q, gaps[c.source],
					strings.Join(m.trace[max(at-5, 0):min(at+60, len(m.trace))], "\n  "))
				break
			}
		}
		for _, q := range slices.Sorted(maps.Keys(c.drLost)) {
			// Потеря в хвосте нумерации видна со следующей записью; журнал,
			// который больше не пишет (гейтвей кончился), её не покажет.
			if q > lastSeq[c.source] {
				continue
			}
			if !back[c.source][q] && !c.gapLost[q] && !covered(gaps[c.source], q) {
				m.fail("принятая %s/%d потеряна с диском, а события пропуска в цепи нет (пропуски: %v)", c.source, q, gaps[c.source])
				break
			}
		}
	}
	m.checkVerdicts(gwPos, gwSeq, verdicts, gwKey)
	cur := monthStart(m.clk.now())
	for _, ki := range keys {
		if got, want := lastKey[ki.Scope], keyLabel(ki); got != want {
			m.fail("квитанция ключа %s в цепи %q, а в кейринге %q", ki.Scope, got, want)
		}
		if _, month, ok := scopeOf(ki.Scope); ok && month.Before(cur) && ki.State == keyring.Active &&
			m.clk.now().Sub(cur) > deactivationGrace+time.Minute {
			m.fail("ключ прошлого месяца %s не закрыт", ki.Scope)
		}
	}
}

// checkVerdicts — у каждой улики журнала гейтвея ровно один вердикт, и он тот
// же, что у чистого прогона тех же строк в порядке журнала улик.
func (m *storeSim) checkVerdicts(gwPos []uint64, gwSeq map[uint64]uint64, verdicts map[uint64][]gateway.Verdict, key ed25519.PublicKey) {
	var c *simClient
	for _, cl := range m.clients {
		if cl.lines != nil {
			c = cl
		}
	}
	tr := gateway.NewTracker(key)
	for _, pos := range gwPos {
		want := tr.Check(c.lines[gwSeq[pos]-1])
		got := verdicts[pos]
		switch {
		case len(got) != 1:
			m.fail("улика гейтвея на позиции %d (номер %d): вердиктов в цепи %d", pos, gwSeq[pos], len(got))
			return
		case fmt.Sprintf("%+v", got[0]) != fmt.Sprintf("%+v", want):
			m.fail("улика гейтвея на позиции %d (номер %d): вердикт %+v, а чистый прогон даёт %+v", pos, gwSeq[pos], got[0], want)
			return
		}
	}
	for pos := range verdicts {
		if _, ok := gwSeq[pos]; !ok {
			m.fail("вердикт на позиции %d, а улики гейтвея там нет", pos)
			return
		}
	}
}

// checkNoResurrection — уничтоженный ключ не поднимается ни из одной прежней
// копии keyring.dat и ни из резерва: их корни уничтожены поворотом.
func (m *storeSim) checkNoResurrection(keys []keyring.KeyInfo) {
	var gone []string
	for _, ki := range keys {
		if ki.State == keyring.Destroyed && !ki.EffectiveAt.IsZero() {
			gone = append(gone, ki.Scope)
		}
	}
	if len(gone) == 0 {
		return
	}
	copies := slices.Clone(m.oldKeyrings)
	if data, err := os.ReadFile(filepath.Join(m.cfg.Keys.BackupDir, keyring.FileName)); err == nil {
		copies = append(copies, data)
	}
	roots := m.newDir("roots-check")
	if err := os.CopyFS(roots, os.DirFS(m.cfg.RootsDir)); err != nil {
		m.t.Fatal(err)
	}
	for i, data := range copies {
		dir := m.newDir("keyring-check")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			m.t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, keyring.FileName), data, 0o600); err != nil {
			m.t.Fatal(err)
		}
		k, err := keyring.Open(dir, keyring.FileRoots{Dir: roots}, keyring.Options{})
		if err != nil {
			continue // корень копии уничтожен: она мертва
		}
		for _, ki := range k.List() {
			if slices.Contains(gone, ki.Scope) && ki.State != keyring.Destroyed {
				m.fail("уничтоженный ключ %s поднимается из прежней копии keyring.dat №%d (%v)", ki.Scope, i, ki.State)
			}
		}
		k.Close()
	}
}

// checkRecord — номер q источника: есть и доказуем, если послан; тело то,
// что слал клиент; обещание выполнено.
func (m *storeSim) checkRecord(c *simClient, q uint64, trust proof.Trust) {
	p, acked := c.acked[q]
	b, err := m.s.Proof(c.source, q, true)
	switch {
	case errors.Is(err, ErrNotFound) && acked && c.drLost[q]:
		return // потеряна вместе с диском: видна должна быть пропуском (check)
	case errors.Is(err, ErrNotFound) && acked:
		m.fail("принятая %s/%d пропала", c.source, q)
		return
	case errors.Is(err, ErrNotFound) && !c.skipped[q]:
		m.fail("посланная %s/%d не принята", c.source, q)
		return
	case errors.Is(err, ErrNotFound):
		return
	case err != nil:
		m.fail("пакет %s/%d: %v", c.source, q, err)
		return
	case c.skipped[q]:
		m.fail("номер %s/%d клиент пропустил, а он принят", c.source, q)
		return
	}
	rep := proof.Verify(b, trust)
	if !rep.Valid() {
		// Ниже в журнале гейтвея — запись, потерянная с диском: сцепка честно
		// разорвана, и не проходят только проверки гейтвея (сам вердикт сверен
		// с чистым прогоном в checkVerdicts).
		hole := c.lines != nil && slices.ContainsFunc(slices.Collect(maps.Keys(c.drLost)), func(x uint64) bool { return x < q })
		for _, ch := range rep.Checks {
			if !ch.OK && !(hole && strings.Contains(ch.Name, "гейтвея")) {
				m.fail("пакет %s/%d не проходит проверку: %s: %s", c.source, q, ch.Name, ch.Detail)
				return
			}
		}
		if !hole {
			return
		}
	}
	sealed, err := evidence.Unmarshal(b.Evidence)
	if err != nil {
		m.fail("%s/%d: %v", c.source, q, err)
		return
	}
	ki, _ := m.s.keyInfo(sealed.Scope())
	erased := ki.State == keyring.Pending || ki.State == keyring.Destroyed
	switch {
	case len(b.DEK) == 0 && !erased:
		m.fail("%s/%d: ключ %s жив (%v), а ключ записи не выдан", c.source, q, ki.Scope, ki.State)
	case len(b.DEK) > 0 && erased:
		m.fail("%s/%d: ключ %s %v, а ключ записи выдан", c.source, q, ki.Scope, ki.State)
	case len(b.DEK) > 0:
		body, err := keyring.OpenWithDEK(sealed.Envelope, b.DEK)
		if err != nil {
			m.fail("%s/%d: тело не вскрыть: %v", c.source, q, err)
		} else if string(body) != c.bodies[q] {
			m.fail("%s/%d: в хранилище тело %q, а клиент слал %q", c.source, q, body, c.bodies[q])
		}
	}
	if acked {
		var linkTime int64
		for _, l := range b.Links {
			if l.Seq == rep.LinkSeq {
				linkTime = l.UnixNano
			}
		}
		if err := proof.CheckPromise(p, rep, linkTime); err != nil {
			// Улика доехала до копии, а её звено — нет: подъём из копии вплетает
			// её в цепь позже срока; обещание нарушено видимо (README).
			late := strings.Contains(err.Error(), "позже обещанного срока") &&
				slices.ContainsFunc(m.restoredAt, func(t time.Time) bool { return t.UnixNano() >= p.ReceivedAt })
			if !late {
				m.fail("обещание %s/%d не выполнено: %v", c.source, q, err)
			}
		}
	}
}
