// Package witness — свидетель голов по C2SP (tlog-witness): принимает от
// хранилища голову с доказательством продолжения и подписывает её своим
// ключом (cosignature/v1), только если она продолжает последнюю, которую он
// подписал для этого хранилища.
//
// ЗАЧЕМ ОТДЕЛЬНО ОТ ХРАНИЛИЩА. Свидетель держит не администратор хранилища:
// регулятор, банк-партнёр, аудиторская фирма. Ему не нужны ни улики, ни ключи
// записи к чему-либо: только открытый ключ хранилища и одна последняя голова
// на хранилище. Голова, которая не продолжает последнюю, подписи не получает
// (422). В журнал отказов ложится только настоящая улика второй истории: голова
// того же размера, что подписанная, с другим корнем — обе подписаны
// хранилищем. Несошедшееся доказательство продолжения уликой не служит: его
// подставляет отправитель, и прислать мусор может кто угодно.
//
// Сверка размера и запись нового состояния — под одним замком и до ответа
// (tlog-witness: иначе два запроса подряд откатили бы состояние), а каталог
// состояния — под flock: второй процесс над тем же каталогом не стартует.
//
// СВИДЕТЕЛЬ НЕ ЗАБЫВАЕТ. Каждая подписанная голова дописывается ещё и в
// журнал подписанного (cosigned.jsonl). Если состояние хранилища пропало или
// старше журнала (файл убрали, каталог state подняли из старой копии),
// свидетель не стартует: с забытой головы он подписал бы тем же ключом вторую
// историю — ровно то, что он должен ловить (tlog-cosignature: подписи свидетеля
// не убывают). Продолжить после такой потери можно только новым ключом.
package witness

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
)

// MaxBody — предел тела add-checkpoint: 63 строки доказательства и заметка с
// подписями — несколько килобайт у хранилища; запас — на заметки с
// постквантовыми подписями (signed-note велит принимать хотя бы 16 подписей).
const MaxBody = 256 << 10

// Log — журнал, который свидетель подписывает: происхождение и ключ
// хранилища (подпись заметки, тип 0x01).
type Log struct {
	Origin string
	Key    ed25519.PublicKey
}

// state — последняя подписанная голова журнала. Note — заметка точки: текст,
// подпись журнала (только его ключом) и подпись свидетеля; её отдаёт GET
// …/checkpoint. Time — время этой подписи: следующая не раньше, пока часы
// отступили меньше чем на maxClockStepBack (подстройка NTP); отступили больше
// — часы шли вперёд и их поправили, подписи снова берут текущее время.
type state struct {
	Origin string `json:"origin"`
	Size   uint64 `json:"size"`
	Root   []byte `json:"root"`
	Time   uint64 `json:"time"`
	Note   string `json:"note"`
}

// Server — свидетель над каталогом состояния dir.
type Server struct {
	signer cosign.Signer
	logs   map[string]Log
	dir    string
	log    *slog.Logger
	// Now — часы подписей; тесты подставляют свои.
	Now func() time.Time

	mu    sync.Mutex
	state map[string]*state
	// ledger — журнал подписанного, открыт на дописывание; под mu.
	ledger *os.File
	// refused — уже записанные отказы (origin, размер, корень): повтор той же
	// развилки журнал не раздувает. lastWarn — последняя строка в журнал
	// процесса о несошедшемся доказательстве: не чаще раза в минуту.
	refusedMu sync.Mutex
	refused   map[string]bool
	lastWarn  time.Time
}

// stateDir, refusedFile и cosignedFile — в каталоге данных свидетеля.
const (
	stateDir     = "state"
	refusedFile  = "refused.jsonl"
	cosignedFile = "cosigned.jsonl"
)

// maxClockStepBack — на сколько часы могут отступить от времени последней
// подписи, и подписи всё ещё идут с её временем (не назад).
const maxClockStepBack = 10 * time.Minute

// cosignedRecord — строка журнала подписанного: голова, которую свидетель
// подписал, и время подписи.
type cosignedRecord struct {
	Origin string `json:"origin"`
	Size   uint64 `json:"size"`
	Root   []byte `json:"root"`
	Time   uint64 `json:"time"`
}

// New открывает свидетеля: читает состояние каждого журнала из dir/state.
// Замок на dir берёт вызывающий (Lock): тестам он не нужен.
func New(signer cosign.Signer, logs []Log, dir string, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	s := &Server{signer: signer, logs: map[string]Log{}, dir: dir, log: log, Now: time.Now, state: map[string]*state{}, refused: map[string]bool{}}
	for _, l := range logs {
		if !cosign.ValidName(l.Origin) || len(l.Key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("witness: log %q: bad origin or key", l.Origin)
		}
		if _, dup := s.logs[l.Origin]; dup {
			return nil, fmt.Errorf("witness: log %q is listed twice", l.Origin)
		}
		s.logs[l.Origin] = l
	}
	if err := os.MkdirAll(filepath.Join(dir, stateDir), 0o700); err != nil {
		return nil, err
	}
	for origin := range s.logs {
		data, err := os.ReadFile(s.statePath(origin))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var st state
		if err := json.Unmarshal(data, &st); err != nil || st.Origin != origin || len(st.Root) != 32 {
			// Испорченное состояние — не «ещё не подписывали»: с нуля свидетель
			// подписал бы любую историю. Остановка, решает человек.
			return nil, fmt.Errorf("witness: state of %s (%s) does not parse; starting from nothing would cosign any history under this key: %s", origin, s.statePath(origin), newKeyAdvice)
		}
		s.state[origin] = &st
	}
	last, err := readLedger(filepath.Join(dir, cosignedFile))
	if err != nil {
		return nil, err
	}
	for origin, rec := range last {
		if _, ok := s.logs[origin]; !ok {
			continue
		}
		st := s.state[origin]
		switch {
		case st == nil:
			return nil, fmt.Errorf("witness: the state of %s is missing, and this witness has cosigned its head %d before (%s); starting from nothing would cosign a second history under this key: %s", origin, rec.Size, cosignedFile, newKeyAdvice)
		case rec.Size > st.Size || rec.Size == st.Size && !bytes.Equal(rec.Root, st.Root):
			return nil, fmt.Errorf("witness: the state of %s holds head %d, older than head %d this witness has cosigned (%s): it was restored from an older copy; going on would cosign a second history under this key: %s", origin, st.Size, rec.Size, cosignedFile, newKeyAdvice)
		}
	}
	if s.ledger, err = os.OpenFile(filepath.Join(dir, cosignedFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err != nil {
		return nil, err
	}
	return s, nil
}

// newKeyAdvice — что делать свидетелю, который не помнит, что подписал.
const newKeyAdvice = "start a new witness with a new key (eswitness init with a new data_dir) and give its verifier key to the store and to auditors; cosignatures of this key stay valid for the history they cover"

// readLedger — последняя подписанная голова каждого журнала по журналу
// подписанного. Оборванная последняя строка (падение посреди записи)
// пропускается: её голова есть в состоянии, записанном раньше.
func readLedger(path string) (map[string]cosignedRecord, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	last := map[string]cosignedRecord{}
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			return last, nil
		}
		if err != nil {
			return nil, err
		}
		var rec cosignedRecord
		if err := json.Unmarshal(line, &rec); err != nil || len(rec.Root) != 32 {
			return nil, fmt.Errorf("witness: %s: a line does not parse: %v", path, err)
		}
		if prev, ok := last[rec.Origin]; !ok || rec.Size >= prev.Size {
			last[rec.Origin] = rec
		}
	}
}

// Close закрывает журнал подписанного.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ledger == nil {
		return nil
	}
	err := s.ledger.Close()
	s.ledger = nil
	return err
}

// statePath — файл состояния журнала: имя — SHA-256 происхождения, как в
// пути GET …/<origin hash>/checkpoint.
func (s *Server) statePath(origin string) string {
	return filepath.Join(s.dir, stateDir, OriginHash(origin)+".json")
}

// OriginHash — SHA-256 происхождения в hex, строчными (tlog-witness).
func OriginHash(origin string) string {
	h := sha256.Sum256([]byte(origin))
	return hex.EncodeToString(h[:])
}

// Handler — POST /add-checkpoint и GET /<origin hash>/checkpoint.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /add-checkpoint", s.addCheckpoint)
	mux.HandleFunc("GET /{origin}/checkpoint", s.checkpoint)
	return mux
}

// emptyRoot — корень пустого дерева RFC 6962: SHA-256 пустой строки.
var emptyRoot = sha256.Sum256(nil)

func (s *Server) addCheckpoint(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		http.Error(w, "request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	old, proof, note, err := cosign.ParseAddCheckpoint(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	text, sigs, err := cosign.SplitNote(note)
	if err != nil {
		http.Error(w, "checkpoint: "+err.Error(), http.StatusBadRequest)
		return
	}
	origin, size, root, err := cosign.ParseCheckpointText(text)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, l := range sigs {
		if _, _, err := cosign.ParseSigLine(l); err != nil {
			http.Error(w, "checkpoint: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	l, ok := s.logs[origin]
	if !ok {
		http.Error(w, "unknown log origin", http.StatusNotFound)
		return
	}
	if err := cosign.VerifyLogSignature(text, sigs, origin, l.Key); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	// В состояние и в GET …/checkpoint — только подпись журнала: чужие строки
	// подписей (и прежние подписи этого свидетеля в присланной заметке) не
	// копятся.
	logLine := logSigLine(sigs, origin, l.Key)
	if old > size {
		http.Error(w, "the old size is larger than the checkpoint size", http.StatusBadRequest)
		return
	}
	if size == 0 && root != emptyRoot {
		http.Error(w, "a checkpoint of size 0 must carry the root of the empty tree", http.StatusUnprocessableEntity)
		return
	}

	// Улика развилки пишется после замка: её fsync не держит других.
	var ev *refusal
	defer func() {
		if ev != nil {
			s.refuse(*ev)
		}
	}()
	// Сверка с последней подписанной и запись новой — под одним замком.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ledger == nil {
		http.Error(w, "the witness is shutting down", http.StatusServiceUnavailable)
		return
	}
	cur := s.state[origin]
	var curSize uint64
	if cur != nil {
		curSize = cur.Size
	}
	if old != curSize {
		w.Header().Set("Content-Type", "text/x.tlog.size")
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "%d\n", curSize)
		return
	}
	switch {
	case old == 0:
		if len(proof) != 0 {
			http.Error(w, "a consistency proof from size 0 must be empty", http.StatusUnprocessableEntity)
			return
		}
	case old == size:
		if len(proof) != 0 {
			// Доказательство от n к n пустое (RFC 6962).
			http.Error(w, "a consistency proof from the checkpoint's own size must be empty", http.StatusUnprocessableEntity)
			return
		}
		if !bytes.Equal(cur.Root, root[:]) {
			// Две головы одного размера с разными корнями, обе подписаны
			// хранилищем: улика второй истории. Пишется вне замка.
			ev = &refusal{Origin: origin, Size: size, Root: root[:], Reason: "the same size as the last cosigned checkpoint with another root", Note: string(text) + "\n" + logLine, Cosigned: cur.Note}
			http.Error(w, "the checkpoint has the size of the last cosigned one and another root", http.StatusUnprocessableEntity)
			return
		}
	default:
		p := make(tlog.TreeProof, len(proof))
		for i, h := range proof {
			p[i] = tlog.Hash(h)
		}
		if err := tlog.CheckTree(p, int64(size), tlog.Hash(root), int64(old), tlog.Hash(cur.Root)); err != nil {
			// Доказательство подставляет отправитель: несошедшееся — не улика
			// развилки (мусор пришлёт кто угодно), в журнал отказов не идёт.
			s.warnProof(origin, old, size)
			http.Error(w, "the consistency proof does not verify", http.StatusUnprocessableEntity)
			return
		}
	}

	now := uint64(max(s.Now().Unix(), 1))
	ts := now
	if cur != nil && cur.Time > now {
		if cur.Time-now <= uint64(maxClockStepBack/time.Second) {
			ts = cur.Time
		} else {
			s.log.Warn("witness: the clock is far behind the time of the last cosignature (a clock that ran ahead was set right?): cosignatures take the current time again", "origin", origin, "last", time.Unix(int64(cur.Time), 0).UTC(), "now", time.Unix(int64(now), 0).UTC())
		}
	}
	line := cosign.SigLine(s.signer.Name, s.signer.Cosign(text, ts))
	next := &state{Origin: origin, Size: size, Root: root[:], Time: ts, Note: string(text) + "\n" + logLine + line}
	// Состояние — на диске до ответа: подпись, которой свидетель потом не
	// помнит, позволила бы ему подписать развилку от прежней головы. Потом —
	// строка журнала подписанного (отстать от состояния ему можно, обогнать —
	// нет: тогда старт принял бы целое состояние за откат).
	if err := s.persist(next); err != nil {
		s.log.Error("witness: saving the state", "origin", origin, "err", err)
		http.Error(w, "the witness could not save its state", http.StatusInternalServerError)
		return
	}
	s.state[origin] = next
	if err := s.appendLedger(cosignedRecord{Origin: origin, Size: size, Root: root[:], Time: ts}); err != nil {
		s.log.Error("witness: writing the journal of cosigned heads", "origin", origin, "err", err)
		http.Error(w, "the witness could not save its state", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, line)
}

// checkpoint — последняя подписанная голова журнала с подписями журнала и
// свидетеля (tlog-witness, monitoring).
func (s *Server) checkpoint(w http.ResponseWriter, r *http.Request) {
	want := r.PathValue("origin")
	s.mu.Lock()
	var note string
	for origin, st := range s.state {
		if OriginHash(origin) == want {
			note = st.Note
		}
	}
	s.mu.Unlock()
	if note == "" {
		http.Error(w, "no checkpoint cosigned for this log", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, note)
}

// persist пишет состояние атомарно: временный файл, fsync, переименование,
// fsync каталога.
func (s *Server) persist(st *state) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	path := s.statePath(st.Origin)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// refusal — строка журнала отказов: голова того же размера, что подписанная
// свидетелем, с другим корнем. Note — её текст с подписью хранилища, Cosigned
// — подписанная заметка свидетеля над прежней головой: вместе — две подписи
// хранилища над разными корнями одного размера.
type refusal struct {
	At       time.Time `json:"at"`
	Origin   string    `json:"origin"`
	Size     uint64    `json:"size"`
	Root     []byte    `json:"root"`
	Reason   string    `json:"reason"`
	Note     string    `json:"note"`
	Cosigned string    `json:"cosigned"`
}

// refuse записывает отказ в журнал отказов (refused.jsonl) один раз на
// развилку и в журнал процесса. Отказ записи журнала отказа не отменяет.
func (s *Server) refuse(ev refusal) {
	s.log.Error("witness: refused a checkpoint signed by the log: it has the size of the one cosigned before and another root, the log shows a second history", "origin", ev.Origin, "size", ev.Size)
	key := ev.Origin + "/" + strconv.FormatUint(ev.Size, 10) + "/" + hex.EncodeToString(ev.Root)
	s.refusedMu.Lock()
	defer s.refusedMu.Unlock()
	if s.refused[key] {
		return
	}
	ev.At = s.Now().UTC()
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(s.dir, refusedFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err == nil {
		_, err = f.Write(append(line, '\n'))
		err = errors.Join(err, f.Sync(), f.Close())
	}
	if err != nil {
		s.log.Error("witness: writing the refusal journal", "err", err)
		return
	}
	s.refused[key] = true
}

// warnProof — несошедшееся доказательство продолжения: строка в журнал
// процесса не чаще раза в минуту.
func (s *Server) warnProof(origin string, old, size uint64) {
	s.refusedMu.Lock()
	defer s.refusedMu.Unlock()
	if now := s.Now(); now.Sub(s.lastWarn) >= time.Minute {
		s.lastWarn = now
		s.log.Warn("witness: a consistency proof does not verify (the sender gave a wrong proof, or the log shows a second history)", "origin", origin, "old", old, "size", size)
	}
}

// appendLedger дописывает строку в журнал подписанного с fsync. Звать под mu.
func (s *Server) appendLedger(rec cosignedRecord) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := s.ledger.Write(append(line, '\n')); err != nil {
		return err
	}
	return s.ledger.Sync()
}

// logSigLine — первая строка подписи журнала с его именем и номером ключа, как
// пришла (VerifyLogSignature её уже проверил): в заметке свидетеля у одного
// ключа одна строка (tlog-checkpoint).
func logSigLine(sigs []string, origin string, key ed25519.PublicKey) string {
	id := cosign.KeyID(origin, cosign.TypeEd25519, key)
	for _, l := range sigs {
		name, sig, err := cosign.ParseSigLine(l)
		if err == nil && name == origin && binary.BigEndian.Uint32(sig) == id {
			return l + "\n"
		}
	}
	return ""
}

// Latest — размер последней подписанной головы журнала (для тестов и
// оператора).
func (s *Server) Latest(origin string) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state[origin]
	if st == nil {
		return 0, false
	}
	return st.Size, true
}

// String — свидетель для журнала процесса.
func (s *Server) String() string {
	return s.signer.Name + " (" + strconv.Itoa(len(s.logs)) + " logs)"
}
