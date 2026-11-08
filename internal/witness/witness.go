// Package witness — свидетель голов по C2SP (tlog-witness): принимает от
// хранилища голову с доказательством продолжения и подписывает её своим
// ключом (cosignature/v1), только если она продолжает последнюю, которую он
// подписал для этого хранилища.
//
// ЗАЧЕМ ОТДЕЛЬНО ОТ ХРАНИЛИЩА. Свидетель держит не администратор хранилища:
// регулятор, банк-партнёр, аудиторская фирма. Ему не нужны ни улики, ни ключи
// записи к чему-либо: только открытый ключ хранилища и одна последняя голова
// на хранилище. Голова, которая не продолжает последнюю, подписи не получает
// (422), а запрос с верной подписью хранилища ложится в журнал отказов: это
// улика того, что хранилище показывает вторую историю.
//
// Сверка размера и запись нового состояния — под одним замком и до ответа
// (tlog-witness: иначе два запроса подряд откатили бы состояние), а каталог
// состояния — под flock: второй процесс над тем же каталогом не стартует.
package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
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
// подписями — несколько килобайт.
const MaxBody = 64 << 10

// Log — журнал, который свидетель подписывает: происхождение и ключ
// хранилища (подпись заметки, тип 0x01).
type Log struct {
	Origin string
	Key    ed25519.PublicKey
}

// state — последняя подписанная голова журнала. Note — заметка точки с
// подписью журнала и подписью свидетеля: её отдаёт GET …/checkpoint. Time —
// время этой подписи: следующая не раньше (подписи свидетеля идут по
// времени, даже если часы машины отступят).
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
}

// stateDir и refusedFile — в каталоге данных свидетеля.
const (
	stateDir    = "state"
	refusedFile = "refused.jsonl"
)

// New открывает свидетеля: читает состояние каждого журнала из dir/state.
// Замок на dir берёт вызывающий (Lock): тестам он не нужен.
func New(signer cosign.Signer, logs []Log, dir string, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	s := &Server{signer: signer, logs: map[string]Log{}, dir: dir, log: log, Now: time.Now, state: map[string]*state{}}
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
			return nil, fmt.Errorf("witness: state of %s (%s) does not parse: restore it from a backup; starting from nothing would cosign any history", origin, s.statePath(origin))
		}
		s.state[origin] = &st
	}
	return s, nil
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
	l, ok := s.logs[origin]
	if !ok {
		http.Error(w, "unknown log origin", http.StatusNotFound)
		return
	}
	if err := cosign.VerifyLogSignature(text, sigs, origin, l.Key); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if old > size {
		http.Error(w, "the old size is larger than the checkpoint size", http.StatusBadRequest)
		return
	}
	if size == 0 && root != emptyRoot {
		s.refuse(origin, old, size, root, "a checkpoint of size 0 with a root other than the empty tree", note)
		http.Error(w, "a checkpoint of size 0 must carry the root of the empty tree", http.StatusUnprocessableEntity)
		return
	}

	// Сверка с последней подписанной и запись новой — под одним замком.
	s.mu.Lock()
	defer s.mu.Unlock()
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
		if !bytes.Equal(cur.Root, root[:]) {
			s.refuse(origin, old, size, root, "the same size as the last cosigned checkpoint with another root", note)
			http.Error(w, "the checkpoint has the size of the last cosigned one and another root", http.StatusUnprocessableEntity)
			return
		}
	default:
		p := make(tlog.TreeProof, len(proof))
		for i, h := range proof {
			p[i] = tlog.Hash(h)
		}
		if err := tlog.CheckTree(p, int64(size), tlog.Hash(root), int64(old), tlog.Hash(cur.Root)); err != nil {
			s.refuse(origin, old, size, root, "the consistency proof from the last cosigned checkpoint does not verify", note)
			http.Error(w, "the consistency proof does not verify", http.StatusUnprocessableEntity)
			return
		}
	}

	ts := uint64(max(s.Now().Unix(), 1))
	if cur != nil && cur.Time > ts {
		ts = cur.Time
	}
	line := cosign.SigLine(s.signer.Name, s.signer.Cosign(text, ts))
	next := &state{Origin: origin, Size: size, Root: root[:], Time: ts, Note: string(note) + line}
	// Состояние — на диске до ответа: подпись, которой свидетель потом не
	// помнит, позволила бы ему подписать развилку от прежней головы.
	if err := s.persist(next); err != nil {
		s.log.Error("witness: saving the state", "origin", origin, "err", err)
		http.Error(w, "the witness could not save its state", http.StatusInternalServerError)
		return
	}
	s.state[origin] = next
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

// refusal — строка журнала отказов: голова с верной подписью хранилища,
// которая не продолжает последнюю подписанную. Улика второй истории.
type refusal struct {
	At     time.Time `json:"at"`
	Origin string    `json:"origin"`
	Old    uint64    `json:"old"`
	Size   uint64    `json:"size"`
	Root   []byte    `json:"root"`
	Reason string    `json:"reason"`
	Note   string    `json:"note"`
}

// refuse записывает отказ в журнал отказов (refused.jsonl) и в журнал
// процесса. Отказ записи журнала отказа не отменяет.
func (s *Server) refuse(origin string, old, size uint64, root [32]byte, reason string, note []byte) {
	s.log.Error("witness: refused a checkpoint signed by the log: it does not extend the last one cosigned", "origin", origin, "old", old, "size", size, "reason", reason)
	line, err := json.Marshal(refusal{At: s.Now().UTC(), Origin: origin, Old: old, Size: size, Root: root[:], Reason: reason, Note: string(note)})
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
	}
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
