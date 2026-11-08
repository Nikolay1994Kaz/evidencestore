package store

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Свидетели C2SP (witness.cosigners; DECISIONS п. 34).
//
// Каждому уходят те же головы, что свидетелю S3 (witness.go): голова под
// каждой меткой TSA, голова звена её токена и текущая раз в witness.every —
// не дальше копии наружу, по той же причине (P-11): подъём из копии не
// обрывает цепь раньше головы, которую свидетель уже подписал, иначе следующую
// он бы не подписал никогда. Запрос — add-checkpoint (tlog-witness): размер
// последней головы, которую подписал свидетель, доказательство продолжения от
// неё и заметка точки. Ответ — подпись свидетеля. Хранилище проверяет её
// ключом из конфигурации и только тогда кладёт в журнал подписей
// (data_dir/cosignatures.jsonl, fsync на каждую), а из журнала подписи идут в
// пакеты: у каждого свидетеля — подписанная раньше всех голова не раньше
// закрепляемого звена.
//
// 409 — свидетель называет размер своей последней головы: после запуска
// хранилище его не знает и спрашивает с old 0, как велит tlog-witness. 422 —
// доказательство не сошлось: свидетель держит другую историю этого
// хранилища. Это тревога (evidencestore_cosigner_refused), голова остаётся в
// очереди, решает человек: так свидетель и ловит переписанную цепь.
//
// Журнал подписей не уезжает в копию наружу. После подъёма из копии подписи,
// полученные до потери диска, пропадают, и улики того времени закрепляет
// подпись, полученная после подъёма, — позже (Known limitations).

const cosignFile = "cosignatures.jsonl"

// maxCosignAnswer — предел ответа свидетеля: несколько строк подписей.
const maxCosignAnswer = 64 << 10

type cosigner struct {
	v      cosign.Verifier
	url    string // <url>/add-checkpoint
	client *http.Client

	// Очередь голов — под chainMu, как у свидетеля S3 (queueCosignLocked).
	queue  []witnessHead
	queued uint64

	// size — размер последней головы, которую подписал свидетель; known —
	// размер узнан (из подписи или ответа 409). Меняются только в CosignOnce:
	// обход один.
	size  uint64
	known bool

	okAt    atomic.Int64  // unix-нс последней подписи
	head    atomic.Uint64 // последняя подписанная голова
	errors  atomic.Uint64
	refused atomic.Bool // последний ответ — 422: свидетель видел другую историю
	lastErr atomic.Pointer[string]
}

// cosigRef — подпись в журнале: размер головы, время подписи, где строка; ok
// — подпись проверена ключом свидетеля и голова сверена с цепью (первая
// выдача в пакет).
type cosigRef struct {
	size, at uint64
	off      int64
	n        int
	ok       bool
}

// cosigRecord — строка журнала подписей.
type cosigRecord struct {
	Name string `json:"name"`
	Size uint64 `json:"size"`
	Root []byte `json:"root"`
	Sig  []byte `json:"sig"`
}

// openCosigners заводит свидетелей из конфигурации и поднимает журнал
// подписей построчно, не читая его в память целиком. При запуске строка только
// разбирается: свидетель из конфигурации (имя и номер ключа), корень в 32
// байта, голова не длиннее цепи, у свидетеля — по возрастанию. Подпись и
// сверка с цепью — когда строка впервые идёт в пакет (cosignaturesForLocked):
// проверять при запуске каждую строку стоило бы десятков секунд на год
// журнала у каждого свидетеля. Чужая строка (свидетеля нет в конфигурации)
// остаётся и не идёт никуда; битая или за концом цепи — громко в журнал
// процесса.
func (s *Store) openCosigners() error {
	for _, w := range s.cfg.Witness.Cosigners {
		c, err := newCosigner(w)
		if err != nil {
			return err
		}
		s.cosigners = append(s.cosigners, c)
	}
	s.cosignIdx = map[string][]cosigRef{}
	if len(s.cosigners) == 0 {
		return nil
	}
	path := filepath.Join(s.cfg.DataDir, cosignFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("cosignatures: %w", err)
	}
	byName := map[string]*cosigner{}
	for _, c := range s.cosigners {
		byName[c.v.Name] = c
	}
	n := s.chainSize()
	r := bufio.NewReaderSize(f, 64<<10)
	var off int64
	for {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			if len(line) > 0 {
				// Оборванная строка в конце — запись, прерванная падением:
				// отрезается, чтобы следующая подпись легла с новой строки.
				s.log.Warn("cosignatures: a torn last line is cut", "file", path, "bytes", len(line))
				if err := f.Truncate(off); err != nil {
					f.Close()
					return fmt.Errorf("cosignatures: %w", err)
				}
			}
			break
		}
		if err != nil {
			f.Close()
			return fmt.Errorf("cosignatures: %w", err)
		}
		ref, c, err := parseCosigLine(bytes.TrimSuffix(line, []byte("\n")), byName, n)
		switch {
		case err != nil:
			s.log.Error("cosignatures: a line is not used", "offset", off, "err", err)
		case c != nil:
			ref.off, ref.n = off, len(line)
			refs := s.cosignIdx[c.v.Name]
			// Подписи одного свидетеля — по размеру: следующая не меньше
			// прежней (tlog-cosignature). Повтор того же размера остаётся за
			// первым: первая выдача в пакет проверяет их по порядку, и
			// испорченная первая не прячет верную.
			if len(refs) == 0 || ref.size >= refs[len(refs)-1].size {
				s.cosignIdx[c.v.Name] = append(refs, ref)
				c.head.Store(ref.size)
			}
		}
		off += int64(len(line))
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return err
	}
	s.cosignLog = f
	return nil
}

// parseCosigLine разбирает строку журнала без проверки подписи. c — её
// свидетель; nil без ошибки — свидетеля или этого его ключа нет в
// конфигурации. n — длина цепи.
func parseCosigLine(line []byte, byName map[string]*cosigner, n uint64) (cosigRef, *cosigner, error) {
	var r cosigRecord
	if err := json.Unmarshal(line, &r); err != nil {
		return cosigRef{}, nil, err
	}
	c := byName[r.Name]
	if c == nil || len(r.Sig) < 4 || binary.BigEndian.Uint32(r.Sig) != c.v.ID {
		return cosigRef{}, nil, nil
	}
	if len(r.Root) != 32 || r.Size == 0 || len(r.Sig) != cosign.BlobSize {
		return cosigRef{}, nil, fmt.Errorf("witness %s: head %d does not parse (root of %d bytes, cosignature of %d)", r.Name, r.Size, len(r.Root), len(r.Sig))
	}
	if r.Size > n {
		return cosigRef{}, nil, fmt.Errorf("witness %s cosigned head %d, and this chain has %d links: the store lost the end of its chain, or the file comes from another chain", r.Name, r.Size, n)
	}
	return cosigRef{size: r.Size, at: binary.BigEndian.Uint64(r.Sig[4:12])}, c, nil
}

func newCosigner(w config.Cosigner) (*cosigner, error) {
	v, err := cosign.ParseVerifier(w.Key)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if w.CA != "" {
		pem, err := os.ReadFile(w.CA)
		if err != nil {
			return nil, fmt.Errorf("witness %s: ca: %w", v.Name, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("witness %s: ca %s holds no PEM certificates", v.Name, w.CA)
		}
		tc.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tc
	return &cosigner{
		v:      v,
		url:    strings.TrimRight(w.URL, "/") + "/add-checkpoint",
		client: &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}, nil
}

// queueCosignLocked ставит голову в очередь каждому свидетелю C2SP: как у
// свидетеля S3, головы под метками остаются все, текущая — одна, последняя.
// Звать под chainMu.
func (s *Store) queueCosignLocked(h witnessHead) {
	if h.size == 0 {
		return
	}
	for _, c := range s.cosigners {
		if h.size <= c.queued {
			continue
		}
		if n := len(c.queue); n > 0 && !c.queue[n-1].stamped {
			c.queue = c.queue[:n-1]
		}
		c.queue = append(c.queue, h)
		c.queued = h.size
	}
}

// CosignOnce ставит в очередь текущую голову и отправляет каждому свидетелю
// его очередь по порядку, не дальше копии наружу. Свидетели — параллельно:
// медленный или зависший не съедает время обхода у остальных, и ошибка одного
// других не держит. Поля cosigner меняет только его горутина; очередь — под
// chainMu, журнал — под cosignMu.
func (s *Store) CosignOnce(ctx context.Context) error {
	if len(s.cosigners) == 0 {
		return nil
	}
	s.chainMu.Lock()
	s.queueCosignLocked(witnessHead{size: s.tree.size(), root: s.tree.root()})
	s.chainMu.Unlock()
	limit := ^uint64(0)
	if s.replicaRemote != nil {
		limit = s.replicaShipped.Load()
	}
	errs := make([]error, len(s.cosigners))
	var wg sync.WaitGroup
	for i, c := range s.cosigners {
		wg.Go(func() {
			if err := s.cosignQueue(ctx, c, limit); err != nil {
				c.errors.Add(1)
				msg := err.Error()
				c.lastErr.Store(&msg)
				errs[i] = fmt.Errorf("witness %s: %w", c.v.Name, err)
			}
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}

// cosignQueue отправляет свидетелю c его очередь: голова за головой, каждая
// уходит из очереди, когда свидетель её подписал или уже подписал новее.
func (s *Store) cosignQueue(ctx context.Context, c *cosigner, limit uint64) error {
	s.chainMu.Lock()
	queue := append([]witnessHead(nil), c.queue...)
	s.chainMu.Unlock()
	for _, h := range queue {
		if h.size > limit {
			break // очередь по возрастанию: дальше — тоже за копией
		}
		if err := s.cosignHead(ctx, c, h); err != nil {
			return err
		}
		s.chainMu.Lock()
		if len(c.queue) > 0 && c.queue[0] == h {
			c.queue = c.queue[1:]
		}
		s.chainMu.Unlock()
	}
	return nil
}

// errCosignRefused — свидетель отверг доказательство продолжения (422): он
// подписал другую историю этого хранилища.
var errCosignRefused = errors.New("the witness refused the head: the consistency proof from the last head it cosigned does not verify, so it holds another history of this store's chain (a rewrite, or a data_dir restored without the heads it had seen); intervene")

// cosignHead добивается подписи головы h: с размером, который знает
// свидетель, а на 409 — с тем, что он назвал. Голова старше последней
// подписанной свидетелем не нужна: из очереди без запроса.
func (s *Store) cosignHead(ctx context.Context, c *cosigner, h witnessHead) error {
	for range 2 {
		if c.known && c.size > s.chainSize() {
			// Тревога держится, пока так: головы младше не уходят из очереди
			// молча. Размер в следующем обходе — снова у свидетеля (old 0,
			// 409): владелец свидетеля мог принять новую историю, сбросив его
			// состояние, и тогда тревога снимается сама.
			size := c.size
			c.known = false
			return fmt.Errorf("the witness has cosigned head %d, and this chain has fewer links: the store lost the end of its chain (restored from an older copy?) or the witness saw another history; intervene", size)
		}
		if c.known && (c.size > h.size || c.size == h.size && s.hasCosig(c.v.Name, h.size)) {
			return nil
		}
		old := uint64(0)
		if c.known {
			old = c.size
		}
		body, err := s.addCheckpointBody(old, h)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "text/plain; charset=utf-8")
		resp, err := c.client.Do(req)
		if err != nil {
			return err
		}
		answer, err := io.ReadAll(io.LimitReader(resp.Body, maxCosignAnswer+1))
		resp.Body.Close()
		if err != nil {
			return err
		}
		if len(answer) > maxCosignAnswer {
			return fmt.Errorf("the answer is larger than %d bytes", maxCosignAnswer)
		}
		switch resp.StatusCode {
		case http.StatusOK:
			c.refused.Store(false)
			return s.keepCosignature(c, h, answer)
		case http.StatusConflict:
			// Свидетель называет размер своей последней головы. Не число —
			// не повод верить ни ему, ни прежнему знанию.
			size, err := cosign.ParseDecimal(strings.TrimSuffix(string(answer), "\n"))
			if err != nil || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/x.tlog.size") {
				c.known = false
				return fmt.Errorf("409 without the witness's tree size: %q", answer)
			}
			if last := s.lastCosigned(c.v.Name); size < last {
				// Свидетель назвал голову младше той, что уже подписал:
				// он потерял состояние и подпишет с неё любую историю.
				s.log.Error("cosigners: the witness reports an older head than it cosigned before: it lost its state, and from there it would cosign any history of this store; tell its operator", "witness", c.v.Name, "reports", size, "cosigned", last)
			}
			c.size, c.known = size, true
		case http.StatusUnprocessableEntity:
			c.refused.Store(true)
			return errCosignRefused
		default:
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(answer)))
		}
	}
	return errors.New("the witness answered 409 twice in a row")
}

func (s *Store) chainSize() uint64 {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	return s.tree.size()
}

// addCheckpointBody — тело add-checkpoint для головы h от размера old:
// доказательство продолжения из tree.hashes сверяется до отправки, как у
// сборщиков (CollectorCheckpoint): испорченный файл дал бы свидетелю ложную
// развилку.
func (s *Store) addCheckpointBody(old uint64, h witnessHead) ([]byte, error) {
	var p [][32]byte
	if old != 0 && old != h.size {
		s.chainMu.Lock()
		tp, err := tlog.ProveTree(int64(h.size), int64(old), s.tree)
		var oldRoot tlog.Hash
		if err == nil {
			oldRoot, err = tlog.TreeHash(int64(old), s.tree)
		}
		if err == nil && tlog.CheckTree(tp, int64(h.size), tlog.Hash(h.root), int64(old), oldRoot) != nil {
			err = errTreeFile
		}
		s.chainMu.Unlock()
		if err != nil {
			return nil, err
		}
		for _, x := range tp {
			p = append(p, x)
		}
	}
	note := proof.SignCheckpoint(s.signer, h.size, h.root).Note(s.signer.PublicKey())
	return cosign.AddCheckpoint(old, p, note), nil
}

// keepCosignature проверяет ответ 200: среди строк подписей — подпись этого
// свидетеля его ключом над головой h; она ложится в журнал с fsync. Подписи
// других ключей пропускаются.
func (s *Store) keepCosignature(c *cosigner, h witnessHead, answer []byte) error {
	if !bytes.HasSuffix(answer, []byte("\n")) {
		return errors.New("the witness's answer does not end with a newline")
	}
	text := cosign.CheckpointText(proof.OriginFor(s.signer.PublicKey()), h.size, h.root)
	var sig []byte
	var at uint64
	lines := strings.Split(string(answer[:len(answer)-1]), "\n")
	if len(lines) > cosign.MaxSigLines {
		return fmt.Errorf("the witness answered %d signature lines", len(lines))
	}
	for _, l := range lines {
		name, blob, err := cosign.ParseSigLine(l)
		if err != nil {
			return fmt.Errorf("the witness's answer: %w", err)
		}
		if name != c.v.Name || binary.BigEndian.Uint32(blob) != c.v.ID {
			continue
		}
		t, err := c.v.Verify(text, blob)
		if err != nil {
			return fmt.Errorf("the witness's cosignature of head %d: %w", h.size, err)
		}
		if sig == nil {
			sig, at = blob, t
		}
	}
	if sig == nil {
		return errors.New("the witness answered without a cosignature by its configured key (is witness.cosigners key the one eswitness vkey prints?)")
	}
	line, err := json.Marshal(cosigRecord{Name: c.v.Name, Size: h.size, Root: h.root[:], Sig: sig})
	if err != nil {
		return err
	}
	line = append(line, '\n')
	s.cosignMu.Lock()
	defer s.cosignMu.Unlock()
	off, err := s.cosignLog.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("cosignatures: %w", err)
	}
	if _, err = s.cosignLog.Write(line); err == nil {
		err = s.cosignLog.Sync()
	}
	if err != nil {
		// Недописанная строка (диск полон) не склеивается со следующей:
		// отрезается. Подпись в индекс не идёт — свидетель подпишет снова.
		s.cosignLog.Truncate(off)
		return fmt.Errorf("cosignatures: %w", err)
	}
	c.size, c.known = h.size, true
	c.head.Store(h.size)
	c.okAt.Store(time.Now().UnixNano())
	c.lastErr.Store(nil)
	refs := s.cosignIdx[c.v.Name]
	if len(refs) == 0 || h.size > refs[len(refs)-1].size {
		s.cosignIdx[c.v.Name] = append(refs, cosigRef{size: h.size, at: at, off: off, n: len(line)})
	}
	return nil
}

// lastCosigned — последняя голова свидетеля name в журнале подписей, 0 — нет.
func (s *Store) lastCosigned(name string) uint64 {
	s.cosignMu.Lock()
	defer s.cosignMu.Unlock()
	if refs := s.cosignIdx[name]; len(refs) > 0 {
		return refs[len(refs)-1].size
	}
	return 0
}

// hasCosig — в журнале есть подпись свидетеля name над головой size.
func (s *Store) hasCosig(name string, size uint64) bool {
	s.cosignMu.Lock()
	defer s.cosignMu.Unlock()
	refs := s.cosignIdx[name]
	i := sort.Search(len(refs), func(i int) bool { return refs[i].size >= size })
	return i < len(refs) && refs[i].size == size
}

// cosignaturesFor — cosignaturesForLocked под chainMu: для пакетов за окно и
// по источнику, которые собираются без него.
func (s *Store) cosignaturesFor(first, last, evLink uint64) ([]proof.Cosignature, error) {
	if len(s.cosigners) == 0 {
		return nil, nil
	}
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	return s.cosignaturesForLocked(first, last, evLink)
}

// cosignaturesForLocked — подписи свидетелей для пакета из звеньев
// first…last, который закрепляет звено evLink: у каждого свидетеля — подпись
// самой ранней головы не раньше max(evLink, first). Она может лежать и дальше
// конца пакета: тогда проверка назовёт голову, до которой просить пакет.
// Строка, которая идёт в пакет впервые, проверяется ключом свидетеля и
// сверяется с цепью. Подпись не сошлась — строка испорчена и уходит из
// индекса; корня нет в цепи (свидетель видел другую историю, или испорчен
// tree.hashes) — строка остаётся, в пакет идёт следующая. То и другое —
// громко в журнал процесса. Звать под chainMu (порядок: chainMu раньше
// cosignMu).
func (s *Store) cosignaturesForLocked(first, last, evLink uint64) ([]proof.Cosignature, error) {
	if len(s.cosigners) == 0 {
		return nil, nil
	}
	lo := max(evLink, first)
	origin := proof.OriginFor(s.signer.PublicKey())
	s.cosignMu.Lock()
	defer s.cosignMu.Unlock()
	var out []proof.Cosignature
	for _, c := range s.cosigners {
		refs := s.cosignIdx[c.v.Name]
		for i := sort.Search(len(refs), func(i int) bool { return refs[i].size >= lo }); i < len(refs); {
			line := make([]byte, refs[i].n)
			if _, err := s.cosignLog.ReadAt(line, refs[i].off); err != nil {
				return nil, fmt.Errorf("cosignatures: %w", err)
			}
			var r cosigRecord
			if err := json.Unmarshal(bytes.TrimSuffix(line, []byte("\n")), &r); err != nil || r.Size != refs[i].size || r.Name != c.v.Name || len(r.Root) != 32 {
				return nil, fmt.Errorf("cosignatures: the line at offset %d changed under the store", refs[i].off)
			}
			if !refs[i].ok {
				root := [32]byte(r.Root)
				if _, err := c.v.Verify(cosign.CheckpointText(origin, r.Size, root), r.Sig); err != nil {
					s.log.Error("cosignatures: a line is not used", "witness", c.v.Name, "head", r.Size, "offset", refs[i].off, "err", err)
					refs = slices.Delete(refs, i, i+1)
					s.cosignIdx[c.v.Name] = refs
					continue
				}
				if err := s.tree.agreesLocked(r.Size, root); err != nil {
					s.log.Error("cosignatures: the witness cosigned a root this chain does not have at that head: it saw another history of this store, or tree.hashes is damaged", "witness", c.v.Name, "head", r.Size, "offset", refs[i].off, "err", err)
					i++
					continue
				}
				refs[i].ok = true
			}
			out = append(out, proof.Cosignature{Name: r.Name, Size: r.Size, Root: r.Root, Sig: r.Sig})
			break
		}
	}
	return out, nil
}

// CosignerStatus — свидетель C2SP в evidencestore status.
type CosignerStatus struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Head      uint64    `json:"cosigned_head"`
	LastAt    time.Time `json:"last_cosigned_at,omitzero"`
	Errors    uint64    `json:"errors"`
	Refused   bool      `json:"refused,omitempty"`
	LastError string    `json:"last_error,omitempty"`
}

func (s *Store) cosignerStatus() []CosignerStatus {
	var out []CosignerStatus
	for _, c := range s.cosigners {
		st := CosignerStatus{Name: c.v.Name, URL: c.url, Head: c.head.Load(), Errors: c.errors.Load(), Refused: c.refused.Load()}
		if t := c.okAt.Load(); t != 0 {
			st.LastAt = time.Unix(0, t).UTC()
		}
		if e := c.lastErr.Load(); e != nil {
			st.LastError = *e
		}
		out = append(out, st)
	}
	return out
}

// closeCosignLog закрывает журнал подписей (closeFiles).
func (s *Store) closeCosignLog() error {
	if s.cosignLog == nil {
		return nil
	}
	err := s.cosignLog.Close()
	s.cosignLog = nil
	return err
}
