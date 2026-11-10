package store

import (
	"bufio"
	"bytes"
	"cmp"
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
// (data_dir/cosign/cosignatures.jsonl, fsync на каждую), а из журнала подписи
// идут в пакеты: у каждого свидетеля — подписанная раньше всех голова не
// раньше закрепляемого звена.
//
// 409 — свидетель называет размер своей последней головы: после запуска
// хранилище спрашивает его с последней головы этого свидетеля в журнале
// подписей (с нуля — только если подписей ещё нет), и 409 с размером младше
// значит, что свидетель потерял состояние (P-115). 422 — доказательство не
// сошлось: свидетель держит другую историю этого хранилища. Это тревога
// (evidencestore_cosigner_refused), голова остаётся в очереди, решает
// человек: так свидетель и ловит переписанную цепь.
//
// Журнал подписей уезжает в копию наружу вместе с журналом улик и цепью и
// возвращается при подъёме: свидетель хранит только последнюю голову, и
// подпись, которой нет у хранилища, не получить уже никогда. Пропадают только
// подписи, полученные после последнего прохода копии.

// cosignFile — журнал подписей в data_dir. Он едет в копию наружу, как
// журнал улик: кусками по смещению, дописывается только целыми строками.
const cosignFile = "cosign/cosignatures.jsonl"

// maxCosignAnswer — предел ответа свидетеля: несколько строк подписей.
const maxCosignAnswer = 64 << 10

type cosigner struct {
	v cosign.Verifier
	// old — прежние ключи свидетеля (old_keys): головы им не уходят, их
	// подписи из журнала идут в пакеты.
	old    []cosign.Verifier
	url    string // <url>/add-checkpoint
	client *http.Client
	// busy — обход этого свидетеля идёт: у каждого свой цикл, а CosignOnce
	// обходит всех; поля ниже меняет только тот, кто держит busy.
	busy sync.Mutex

	// Очередь голов — под chainMu, как у свидетеля S3 (queueCosignLocked).
	queue  []witnessHead
	queued uint64

	// size — размер последней головы, которую подписал свидетель; known —
	// размер узнан (из подписи или ответа 409). Меняются только под busy.
	size  uint64
	known bool

	okAt    atomic.Int64  // unix-нс последней подписи
	head    atomic.Uint64 // последняя подписанная голова
	errors  atomic.Uint64
	refused atomic.Bool // последний ответ — 422: свидетель видел другую историю
	// lostState — свидетель назвал голову младше той, что он уже подписал по
	// журналу подписей: он потерял состояние и подпишет с неё любую историю.
	lostState atomic.Bool
	lastErr   atomic.Pointer[string]
}

// cosigRef — подпись в журнале: размер головы и где строка; ok — подпись
// проверена ключом свидетеля и голова сверена с цепью; bad — подпись верна,
// а корня в этой цепи нет (свидетель видел другую историю): в пакеты не идёт.
type cosigRef struct {
	size    uint64
	off     int64
	n       int
	ok, bad bool
}

// cosigKey — ключ свидетеля в индексе журнала подписей: имя и номер ключа.
// Подписи прежнего ключа того же свидетеля — под своим cosigKey.
type cosigKey struct {
	name string
	id   uint32
}

func keyOf(v cosign.Verifier) cosigKey { return cosigKey{v.Name, v.ID} }

// keys — ключи свидетеля для пакетов: текущий, за ним прежние.
func (c *cosigner) keys() []cosign.Verifier {
	return append([]cosign.Verifier{c.v}, c.old...)
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
// журнала у каждого свидетеля. Чужая строка (ключа нет в конфигурации — ни
// текущим, ни прежним) остаётся и не идёт никуда; битая или за концом цепи —
// громко в журнал процесса.
func (s *Store) openCosigners() error {
	byKey := map[cosigKey]bool{}
	for _, w := range s.cfg.Witness.Cosigners {
		c, err := newCosigner(w)
		if err != nil {
			return err
		}
		s.cosigners = append(s.cosigners, c)
		for _, v := range c.keys() {
			byKey[keyOf(v)] = true
		}
	}
	s.cosignIdx = map[cosigKey][]cosigRef{}
	if len(s.cosigners) == 0 {
		return nil
	}
	path := filepath.Join(s.cfg.DataDir, filepath.FromSlash(cosignFile))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("cosignatures: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("cosignatures: %w", err)
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
		ref, k, err := parseCosigLine(bytes.TrimSuffix(line, []byte("\n")), byKey, n)
		switch {
		case err != nil:
			s.log.Error("cosignatures: a line is not used", "offset", off, "err", err)
		case k != (cosigKey{}):
			ref.off, ref.n = off, len(line)
			s.cosignIdx[k] = append(s.cosignIdx[k], ref)
		}
		off += int64(len(line))
	}
	// Подписи одного ключа идут по размеру (tlog-cosignature), но строка с
	// завышенным размером (порча) не должна прятать верные после неё: индекс
	// сортируется, повторы одного размера остаются в порядке файла — первая
	// выдача в пакет проверяет их по очереди.
	for k, refs := range s.cosignIdx {
		slices.SortStableFunc(refs, func(a, b cosigRef) int { return cmp.Compare(a.size, b.size) })
		s.cosignIdx[k] = refs
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return err
	}
	s.cosignLog = f
	// Последняя строка текущего ключа каждого свидетеля проверяется сразу: с
	// её головы хранилище спрашивает свидетеля после запуска (lastCosigned),
	// её же показывает status. Не сошлась — берётся предыдущая. Строки прежних
	// ключей — только при выдаче в пакет.
	s.chainMu.Lock()
	s.cosignMu.Lock()
	defer s.chainMu.Unlock()
	defer s.cosignMu.Unlock()
	for _, c := range s.cosigners {
		refs := s.cosignIdx[keyOf(c.v)]
		for len(refs) > 0 {
			ref := &refs[len(refs)-1]
			r, err := s.readCosigLocked(*ref, c.v.Name)
			if err != nil {
				return err
			}
			at, sigErr, rootErr := s.verifyCosigLocked(c.v, r)
			if sigErr == nil && rootErr == nil {
				ref.ok = true
				// Время последней подписи — из неё самой (часы свидетеля, не в
				// будущем): иначе после каждого запуска тревога «давно нет
				// подписи» до первой новой.
				c.okAt.Store(time.Unix(int64(min(at, uint64(time.Now().Unix()))), 0).UnixNano())
				break
			}
			s.log.Error("cosignatures: a line is not used", "witness", c.v.Name, "head", r.Size, "offset", ref.off, "err", errors.Join(sigErr, rootErr))
			refs = refs[:len(refs)-1]
		}
		s.cosignIdx[keyOf(c.v)] = refs
		var head uint64
		if len(refs) > 0 {
			head = refs[len(refs)-1].size
		}
		c.head.Store(head)
	}
	return nil
}

// parseCosigLine разбирает строку журнала без проверки подписи. k — её ключ;
// пустой без ошибки — этого ключа (имени и номера) нет в конфигурации. n —
// длина цепи.
func parseCosigLine(line []byte, byKey map[cosigKey]bool, n uint64) (cosigRef, cosigKey, error) {
	var r cosigRecord
	if err := json.Unmarshal(line, &r); err != nil {
		return cosigRef{}, cosigKey{}, err
	}
	if len(r.Sig) < 4 {
		return cosigRef{}, cosigKey{}, nil
	}
	k := cosigKey{r.Name, binary.BigEndian.Uint32(r.Sig)}
	if !byKey[k] {
		return cosigRef{}, cosigKey{}, nil
	}
	if len(r.Root) != 32 || r.Size == 0 || len(r.Sig) != cosign.BlobSize {
		return cosigRef{}, cosigKey{}, fmt.Errorf("witness %s: head %d does not parse (root of %d bytes, cosignature of %d)", r.Name, r.Size, len(r.Root), len(r.Sig))
	}
	if r.Size > n {
		return cosigRef{}, cosigKey{}, fmt.Errorf("witness %s cosigned head %d, and this chain has %d links: the store lost the end of its chain, or the file comes from another chain", r.Name, r.Size, n)
	}
	return cosigRef{size: r.Size}, k, nil
}

func newCosigner(w config.Cosigner) (*cosigner, error) {
	v, err := cosign.ParseVerifier(w.Key)
	if err != nil {
		return nil, err
	}
	var old []cosign.Verifier
	for _, k := range w.OldKeys {
		ov, err := cosign.ParseVerifier(k)
		if err != nil {
			return nil, fmt.Errorf("witness %s: old_keys: %w", v.Name, err)
		}
		old = append(old, ov)
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
		v:   v,
		old: old,
		url: strings.TrimRight(w.URL, "/") + "/add-checkpoint",
		// Перенаправлений не следуем: свидетель — тот адрес, что в
		// конфигурации, и голова не уходит туда, куда укажет ответ.
		client: &http.Client{Timeout: 30 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
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

// CosignOnce обходит всех свидетелей разом (cosignWitness), параллельно:
// медленный или зависший не съедает время у остальных, и ошибка одного других
// не держит.
func (s *Store) CosignOnce(ctx context.Context) error {
	errs := make([]error, len(s.cosigners))
	var wg sync.WaitGroup
	for i, c := range s.cosigners {
		wg.Go(func() { errs[i] = s.cosignWitness(ctx, c) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// startCosignLoops — фоновый обход: у каждого свидетеля свой цикл раз в
// witness.every, и зависший (до 30 с на запрос) не задаёт ритм остальным.
// Обход бросается, когда хранилище закрывается.
func (s *Store) startCosignLoops() {
	for _, c := range s.cosigners {
		s.loop(s.cfg.Witness.Every.D(), func() {
			ctx, cancel := s.stopCtx(time.Minute)
			defer cancel()
			if err := s.cosignWitness(ctx, c); err != nil {
				s.log.Error("cosigners", "err", err)
			}
		})
	}
}

// cosignWitness ставит в очередь текущую голову копии и отправляет свидетелю
// c его очередь по порядку, не дальше копии наружу. Очередь — под chainMu,
// журнал — под cosignMu, поля c — под c.busy. Голову копии не снять
// (tree.hashes) — очередь всё равно уходит, пока доказательства продолжения
// строятся (головы под метками в ней уже с корнями); ошибка — в счётчик и
// last_error свидетеля.
func (s *Store) cosignWitness(ctx context.Context, c *cosigner) error {
	c.busy.Lock()
	defer c.busy.Unlock()
	s.chainMu.Lock()
	h, ok, headErr := s.shippedHeadLocked()
	if ok {
		s.queueCosignLocked(h)
	}
	s.chainMu.Unlock()
	limit := ^uint64(0)
	if s.replicaRemote != nil {
		limit = s.replicaShipped.Load()
	}
	var err error
	if headErr != nil {
		err = fmt.Errorf("the head for the witnesses: %w", headErr)
	}
	if qerr := s.cosignQueue(ctx, c, limit); qerr != nil {
		err = errors.Join(err, qerr)
	}
	if err != nil {
		c.errors.Add(1)
		msg := err.Error()
		c.lastErr.Store(&msg)
		return fmt.Errorf("witness %s: %w", c.v.Name, err)
	}
	return nil
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
			// молча. Размер в следующем обходе спрашивается у свидетеля
			// заново: знание хранилища могло быть ложным.
			size := c.size
			c.known = false
			return fmt.Errorf("the witness has cosigned head %d, and this chain has fewer links: the store lost the end of its chain (restored from an older copy?) or the witness saw another history; intervene", size)
		}
		// Размер у свидетеля неизвестен (после запуска) — спрашиваем не с нуля,
		// а с последней головы этого свидетеля в журнале подписей: свидетель,
		// потерявший состояние, ответит 409 с меньшим размером — тревога, — а
		// не подпишет с нуля молча любую историю.
		old := c.size
		if !c.known {
			old = s.lastCosigned(c.v)
		}
		if old > h.size || old == h.size && s.hasCosig(c.v, h.size) {
			return nil
		}
		body, err := s.addCheckpointBody(old, h)
		if err != nil {
			return err
		}
		code, ctype, answer, err := c.post(ctx, body)
		if err != nil {
			return err
		}
		switch code {
		case http.StatusOK:
			if err := s.keepCosignature(c, h, answer); err != nil {
				return err
			}
			c.refused.Store(false)
			c.lostState.Store(false)
			return nil
		case http.StatusConflict:
			// Свидетель называет размер своей последней головы. Не число —
			// не повод верить ни ему, ни прежнему знанию.
			size, err := cosign.ParseDecimal(strings.TrimSuffix(string(answer), "\n"))
			if err != nil || !strings.HasPrefix(ctype, "text/x.tlog.size") {
				c.known = false
				return fmt.Errorf("409 without the witness's tree size: %q", answer)
			}
			if last := s.lastCosigned(c.v); size < last {
				c.lostState.Store(true)
				c.known = false
				return fmt.Errorf("the witness reports head %d, older than head %d it has cosigned for this store: it lost its state, and from there it would cosign a second history under the same key; its operator has to start it over with a new key (eswitness init in a new data_dir): the new verifier key goes into witness.cosigners, the old one into that entry's old_keys", size, last)
			}
			c.lostState.Store(false)
			c.size, c.known = size, true
			if size > 0 && size != h.size && size <= s.chainSize() && !s.hasCosig(c.v, size) {
				// Свидетель подписал голову, которой нет в журнале подписей
				// (падение между его ответом и записью): она нужна пакетам,
				// которые на ней кончаются, — просим её снова.
				if err := s.recosign(ctx, c, size); err != nil {
					// В следующем обходе — снова с журнала: 409 вернёт к этой
					// голове, и её подпись будет запрошена ещё раз.
					c.known = false
					return fmt.Errorf("head %d the witness has cosigned, again: %w", size, err)
				}
			}
		case http.StatusUnprocessableEntity:
			c.refused.Store(true)
			return errCosignRefused
		default:
			return fmt.Errorf("HTTP %d: %s", code, strings.TrimSpace(string(answer)))
		}
	}
	return errors.New("the witness answered 409 twice in a row")
}

// post отправляет свидетелю тело add-checkpoint: код ответа, его тип и тело.
func (c *cosigner) post(ctx context.Context, body []byte) (int, string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxCosignAnswer+1))
	if err != nil {
		return 0, "", nil, err
	}
	if len(answer) > maxCosignAnswer {
		return 0, "", nil, fmt.Errorf("the answer is larger than %d bytes", maxCosignAnswer)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), answer, nil
}

// recosign просит свидетеля подписать снова голову m, которую он уже
// подписал (old = size = m, без доказательства), и кладёт подпись в журнал.
func (s *Store) recosign(ctx context.Context, c *cosigner, m uint64) error {
	s.chainMu.Lock()
	root := tlog.Hash(s.tree.root())
	var err error
	if m != s.tree.size() {
		if root, err = tlog.TreeHash(int64(m), s.tree); err == nil {
			err = s.tree.agreesLocked(m, root)
		}
	}
	s.chainMu.Unlock()
	if err != nil {
		return err
	}
	h := witnessHead{size: m, root: root}
	body, err := s.addCheckpointBody(m, h)
	if err != nil {
		return err
	}
	code, _, answer, err := c.post(ctx, body)
	if err != nil {
		return err
	}
	switch code {
	case http.StatusOK:
		return s.keepCosignature(c, h, answer)
	case http.StatusUnprocessableEntity:
		c.refused.Store(true)
		return errCosignRefused
	}
	return fmt.Errorf("HTTP %d: %s", code, strings.TrimSpace(string(answer)))
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
		if _, err := c.v.Verify(text, blob); err != nil {
			return fmt.Errorf("the witness's cosignature of head %d: %w", h.size, err)
		}
		if sig == nil {
			sig = blob
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
	refs := s.cosignIdx[keyOf(c.v)]
	if len(refs) == 0 || h.size > refs[len(refs)-1].size {
		s.cosignIdx[keyOf(c.v)] = append(refs, cosigRef{size: h.size, off: off, n: len(line), ok: true})
	}
	return nil
}

// lastCosigned — последняя голова ключа v в журнале подписей, 0 — нет.
func (s *Store) lastCosigned(v cosign.Verifier) uint64 {
	s.cosignMu.Lock()
	defer s.cosignMu.Unlock()
	if refs := s.cosignIdx[keyOf(v)]; len(refs) > 0 {
		return refs[len(refs)-1].size
	}
	return 0
}

// hasCosig — в журнале есть подпись ключа v над головой size.
func (s *Store) hasCosig(v cosign.Verifier, size uint64) bool {
	s.cosignMu.Lock()
	defer s.cosignMu.Unlock()
	refs := s.cosignIdx[keyOf(v)]
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
// first…last, который закрепляет звено evLink: у каждого ключа свидетеля
// (текущего и прежних) — подпись самой ранней головы не раньше max(evLink,
// first). Она может лежать и дальше конца пакета: тогда проверка назовёт
// голову, до которой просить пакет. Строка, которая идёт в пакет впервые,
// проверяется своим ключом и сверяется с цепью. Подпись не сошлась — строка
// испорчена и уходит из индекса; корня нет в цепи (свидетель видел другую
// историю, или испорчен tree.hashes) — строка помечается и не идёт никуда до
// перезапуска, в пакет идёт следующая. То и другое — громко в журнал
// процесса. Звать под chainMu (порядок: chainMu раньше cosignMu).
func (s *Store) cosignaturesForLocked(first, last, evLink uint64) ([]proof.Cosignature, error) {
	if len(s.cosigners) == 0 {
		return nil, nil
	}
	lo := max(evLink, first)
	s.cosignMu.Lock()
	defer s.cosignMu.Unlock()
	var out []proof.Cosignature
	for _, c := range s.cosigners {
		for _, v := range c.keys() {
			cs, err := s.earliestCosigLocked(v, lo)
			if err != nil {
				return nil, err
			}
			out = append(out, cs...)
		}
	}
	return out, nil
}

// earliestCosigLocked — подпись ключа v над самой ранней головой не раньше
// lo, проверенная (cosignaturesForLocked); нет такой — пусто. Звать под
// chainMu и cosignMu.
func (s *Store) earliestCosigLocked(v cosign.Verifier, lo uint64) ([]proof.Cosignature, error) {
	k := keyOf(v)
	refs := s.cosignIdx[k]
	for i := sort.Search(len(refs), func(i int) bool { return refs[i].size >= lo }); i < len(refs); {
		if refs[i].bad {
			i++
			continue
		}
		r, err := s.readCosigLocked(refs[i], v.Name)
		if err != nil {
			return nil, err
		}
		if !refs[i].ok {
			_, sigErr, rootErr := s.verifyCosigLocked(v, r)
			switch {
			case sigErr != nil:
				s.log.Error("cosignatures: a line is not used", "witness", v.Name, "key", fmt.Sprintf("%08x", v.ID), "head", r.Size, "offset", refs[i].off, "err", sigErr)
				refs = slices.Delete(refs, i, i+1)
				s.cosignIdx[k] = refs
				continue
			case rootErr != nil:
				s.log.Error("cosignatures: the witness cosigned a root this chain does not have at that head: it saw another history of this store, or tree.hashes is damaged", "witness", v.Name, "key", fmt.Sprintf("%08x", v.ID), "head", r.Size, "offset", refs[i].off, "err", rootErr)
				refs[i].bad = true
				i++
				continue
			}
			refs[i].ok = true
		}
		return []proof.Cosignature{{Name: r.Name, Size: r.Size, Root: r.Root, Sig: r.Sig}}, nil
	}
	return nil, nil
}

// readCosigLocked читает строку журнала ref свидетеля name. Звать под
// cosignMu.
func (s *Store) readCosigLocked(ref cosigRef, name string) (cosigRecord, error) {
	line := make([]byte, ref.n)
	if _, err := s.cosignLog.ReadAt(line, ref.off); err != nil {
		return cosigRecord{}, fmt.Errorf("cosignatures: %w", err)
	}
	var r cosigRecord
	if err := json.Unmarshal(bytes.TrimSuffix(line, []byte("\n")), &r); err != nil || r.Size != ref.size || r.Name != name || len(r.Root) != 32 {
		return cosigRecord{}, fmt.Errorf("cosignatures: the line at offset %d changed under the store", ref.off)
	}
	return r, nil
}

// verifyCosigLocked — подпись строки ключом v (sigErr; at — её время) и её
// корень в этой цепи (rootErr). Звать под chainMu.
func (s *Store) verifyCosigLocked(v cosign.Verifier, r cosigRecord) (at uint64, sigErr, rootErr error) {
	root := [32]byte(r.Root)
	at, err := v.Verify(cosign.CheckpointText(proof.OriginFor(s.signer.PublicKey()), r.Size, root), r.Sig)
	if err != nil {
		return 0, err, nil
	}
	return at, nil, s.tree.agreesLocked(r.Size, root)
}

// CosignerStatus — свидетель C2SP в evidencestore status.
type CosignerStatus struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Head      uint64    `json:"cosigned_head"`
	LastAt    time.Time `json:"last_cosigned_at,omitzero"`
	Errors    uint64    `json:"errors"`
	Refused   bool      `json:"refused,omitempty"`
	LostState bool      `json:"lost_state,omitempty"`
	LastError string    `json:"last_error,omitempty"`
}

func (s *Store) cosignerStatus() []CosignerStatus {
	var out []CosignerStatus
	for _, c := range s.cosigners {
		st := CosignerStatus{Name: c.v.Name, URL: c.url, Head: c.head.Load(), Errors: c.errors.Load(), Refused: c.refused.Load(), LostState: c.lostState.Load()}
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

// cosignLogSize — размер журнала подписей для копии наружу: под cosignMu в
// файле только целые строки, уже на диске. ok = false — журнала нет
// (свидетели не настроены).
func (s *Store) cosignLogSize() (int64, bool, error) {
	if s.cosignLog == nil {
		return 0, false, nil
	}
	s.cosignMu.Lock()
	defer s.cosignMu.Unlock()
	fi, err := s.cosignLog.Stat()
	if err != nil {
		return 0, false, err
	}
	return fi.Size(), true, nil
}

// cosignRange — байты from…end журнала подписей для копии наружу: из
// открытого файла (его размер даёт cosignLogSize), а не по пути. Журнал,
// удалённый на ходу, хранилище дописывает и копия дочитывает, и проход копии
// не падает (T). Журнал не открыт (свидетели не настроены) — по пути.
func (s *Store) cosignRange(from, end int64) ([]byte, error) {
	s.cosignMu.Lock()
	defer s.cosignMu.Unlock()
	if s.cosignLog == nil {
		return readRange(filepath.Join(s.cfg.DataDir, filepath.FromSlash(cosignFile)), from, end)
	}
	buf := make([]byte, end-from)
	if _, err := s.cosignLog.ReadAt(buf, from); err != nil {
		return nil, fmt.Errorf("replica: read %s: %w", cosignFile, err)
	}
	return buf, nil
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
