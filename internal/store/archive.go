package store

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Вторая служба меток (tsa.archive; DECISIONS п. 35).
//
// Основная служба ставит метки цепи: T1, T2 и якорь времени приёма. Вторая —
// другого оператора — заверяет головы отдельно, как свидетель: раз в
// tsa.every хранилище берёт у неё метку над головой копии (не дальше копии,
// по той же причине, что у свидетелей, P-11) и кладёт её в журнал
// data_dir/tsa/archive.jsonl (fsync на строку; едет в копию наружу). На T1,
// T2 и время приёма эти метки не влияют: время приёма держится по часам
// основной службы, и T2 по чужим часам, отстающим на долю секунды, называло
// бы честную запись принятой позже T2. Их дело — доказательство
// существования (POE): если сертификат основной отзовут по компрометации
// ключа, метка второй над головой, где лежит токен основной, показывает, что
// токен существовал раньше (RFC 3161, 4; переметка RFC 4998). В пакет идёт,
// для каждого токена пакета, самая ранняя метка второй службы над головой не
// раньше его звена (proof.ArchiveStamp), с доказательством продолжения, если
// голова дальше конца пакета.

// archiveFile — журнал меток второй службы в data_dir; едет в копию наружу,
// как журнал подписей свидетелей.
const archiveFile = "tsa/archive.jsonl"

// archiveRecord — строка журнала: голова и токен второй службы над ней; Key —
// SHA-256 ключа (SubjectPublicKeyInfo), которым токен подписан: службы
// различаются по нему (у строк без него — ключ из токена). Cert — сертификат
// подписанта, когда токен его не несёт (он был в tsa.archive.trust): строка
// годна и после того, как tsa.archive сменили или убрали.
type archiveRecord struct {
	Size  uint64 `json:"size"`
	Root  []byte `json:"root"`
	Token []byte `json:"token"`
	Key   []byte `json:"key,omitempty"`
	Cert  []byte `json:"cert,omitempty"`
}

// signerCerts — сертификаты, которыми искать подписанта строки: доверие
// второй службы и Cert строки.
func (rec archiveRecord) signerCerts(inter []*x509.Certificate) []*x509.Certificate {
	if len(rec.Cert) == 0 {
		return inter
	}
	c, err := x509.ParseCertificate(rec.Cert)
	if err != nil {
		return inter
	}
	return append(slices.Clone(inter), c)
}

// signerKey — SHA-256 ключа, которым подписан токен (нули — не разобрать).
// Сертификат подписанта — из токена или inter: служба может его не класть.
func signerKey(token []byte, inter ...*x509.Certificate) [32]byte {
	k, err := tsa.SignerKey(token, inter...)
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(k)
}

// archiveRef — метка в журнале: размер головы, где строка и чьим ключом
// подписан токен; ok — токен проверен и голова сверена с цепью; bad — не
// сошлось: в пакеты не идёт.
type archiveRef struct {
	size    uint64
	off     int64
	n       int
	key     [32]byte
	ok, bad bool
}

// archiver — вторая служба.
type archiver struct {
	url    string
	trust  tsa.Trust
	client *http.Client

	busy    sync.Mutex // обход один: фоновый цикл и ArchiveOnce
	errors  atomic.Uint64
	okAt    atomic.Int64 // unix-нс последней метки
	head    atomic.Uint64
	lastErr atomic.Pointer[string]
}

// openArchive заводит вторую службу из конфигурации и поднимает её журнал
// построчно: строка разбирается (голова не длиннее цепи, корень в 32 байта,
// токен не длиннее tsa.MaxTokenSize), сверка с цепью и подпись токена —
// когда строка впервые идёт в пакет. Оборванная последняя строка
// отрезается; битая или за концом цепи — громко в журнал процесса. Журнал
// поднимается и без tsa.archive, если он есть: службу сменили или убрали, а
// её прежние метки — POE для записей своего времени — идут в пакеты и
// копию по-прежнему.
func (s *Store) openArchive() error {
	a := s.cfg.TSA.Archive
	path := filepath.Join(s.cfg.DataDir, filepath.FromSlash(archiveFile))
	if a.URL == "" {
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			return nil
		} else if err != nil {
			return fmt.Errorf("tsa archive: %w", err)
		}
	} else {
		trust, err := tsa.LoadTrust(joinPaths(a.Trust))
		if err != nil {
			return fmt.Errorf("tsa.archive: %w", err)
		}
		s.archiver = &archiver{url: a.URL, trust: trust, client: s.tsaHTTP}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("tsa archive: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("tsa archive: %w", err)
	}
	n := s.chainSize()
	r := bufio.NewReaderSize(f, 64<<10)
	var off int64
	for {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			if len(line) > 0 {
				s.log.Warn("tsa archive: a torn last line is cut", "file", path, "bytes", len(line))
				if err := f.Truncate(off); err != nil {
					f.Close()
					return fmt.Errorf("tsa archive: %w", err)
				}
			}
			break
		}
		if err != nil {
			f.Close()
			return fmt.Errorf("tsa archive: %w", err)
		}
		var rec archiveRecord
		switch err := json.Unmarshal(bytes.TrimSuffix(line, []byte("\n")), &rec); {
		case err != nil:
			s.log.Error("tsa archive: a line is not used", "offset", off, "err", err)
		case len(rec.Root) != 32 || rec.Size == 0 || len(rec.Token) == 0 || len(rec.Token) > tsa.MaxTokenSize:
			s.log.Error("tsa archive: a line is not used", "offset", off, "err", "it does not parse")
		case rec.Size > n:
			s.log.Error("tsa archive: a line is not used: its head is beyond the end of this chain (the store lost the end of its chain, or the file comes from another chain)", "offset", off, "head", rec.Size, "chain", n)
		default:
			var inter []*x509.Certificate
			if s.archiver != nil {
				inter = s.archiver.trust.Intermediates
			}
			key := signerKey(rec.Token, rec.signerCerts(inter)...)
			if len(rec.Key) == 32 {
				key = [32]byte(rec.Key)
			}
			s.archiveIdx = append(s.archiveIdx, archiveRef{size: rec.Size, off: off, n: len(line), key: key})
		}
		off += int64(len(line))
	}
	slices.SortStableFunc(s.archiveIdx, func(a, b archiveRef) int { return cmp.Compare(a.size, b.size) })
	s.archiveByKey = map[[32]byte][]int{}
	for i, ref := range s.archiveIdx {
		s.indexArchive(i, ref.key)
	}
	s.archiveLog, s.archiveEnd, s.archiveOn = f, off, true
	if k := len(s.archiveIdx); k > 0 && s.archiver != nil {
		s.archiver.head.Store(s.archiveIdx[k-1].size)
	}
	return nil
}

// startArchiveLoop — фоновый обход второй службы раз в tsa.every; бросается,
// когда хранилище закрывается.
func (s *Store) startArchiveLoop() {
	if s.archiver == nil {
		return
	}
	s.loopNow(s.cfg.TSA.Every.D(), func() {
		ctx, cancel := s.stopCtx(time.Minute)
		defer cancel()
		if err := s.ArchiveOnce(ctx); err != nil {
			s.log.Error("tsa archive", "err", err)
		}
	})
}

// ArchiveOnce берёт у второй службы метку над головой копии, если голова
// ушла дальше последней заверенной, проверяет токен и кладёт его в журнал.
func (s *Store) ArchiveOnce(ctx context.Context) (err error) {
	a := s.archiver
	if a == nil {
		return nil
	}
	a.busy.Lock()
	defer a.busy.Unlock()
	defer func() {
		if err != nil {
			a.errors.Add(1)
			msg := err.Error()
			a.lastErr.Store(&msg)
		}
	}()
	// Ключ основной службы — из её последней проверенной метки (Stamp); после
	// запуска, до первой метки, — раз из последнего токена цепи.
	mainKey := s.tsaKey.Load()
	s.chainMu.Lock()
	h, ok, err := s.shippedHeadLocked()
	var mainToken []byte
	if n := len(s.tokens); mainKey == nil && err == nil && ok && n > 0 {
		mainToken, _ = s.leafPayloadLocked(s.tokens[n-1].leaf)
	}
	s.chainMu.Unlock()
	if mainKey == nil && mainToken != nil {
		if k := signerKey(mainToken, s.tsaTrust.Intermediates...); k != ([32]byte{}) {
			mainKey = &k
			s.tsaKey.CompareAndSwap(nil, mainKey)
		}
	}
	if err != nil {
		return fmt.Errorf("the head to time-stamp: %w", err)
	}
	if !ok || h.size <= a.head.Load() {
		return nil
	}
	imprint := proof.HeadImprint(h.size, h.root)
	token, err := tsa.Request(ctx, a.client, a.url, imprint)
	if err != nil {
		return err
	}
	info, err := tsa.Verify(token, imprint, a.trust)
	if err != nil {
		return fmt.Errorf("the token of %s: %w", a.url, err)
	}
	// Та же служба под другим адресом: её метки после компрометации ключа
	// ничего не покажут, а хранилище иначе молчало бы.
	key := sha256.Sum256(info.Signer.RawSubjectPublicKeyInfo)
	if mainKey != nil && *mainKey == key {
		return fmt.Errorf("%s signs with the key of tsa.url (%q): it is the same TSA, and its time-stamps show nothing once that key is compromised; point tsa.archive at a TSA of another operator", a.url, info.Signer.Subject.String())
	}
	rec := archiveRecord{Size: h.size, Root: h.root[:], Token: token, Key: key[:]}
	if !slices.ContainsFunc(info.Certs, func(c *x509.Certificate) bool { return bytes.Equal(c.Raw, info.Signer.Raw) }) {
		rec.Cert = info.Signer.Raw
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	s.archiveMu.Lock()
	defer s.archiveMu.Unlock()
	if s.archiveLog == nil {
		return errors.New("tsa archive: the store is closing")
	}
	// Пишем с конца последней целой строки: недописанная прежняя (отрезать
	// её не вышло) затирается и со следующей не склеится, а копия наружу
	// берёт только целые строки (archiveLogSize).
	off := s.archiveEnd
	if _, err = s.archiveLog.WriteAt(line, off); err == nil {
		err = s.archiveLog.Sync()
	}
	if err != nil {
		s.archiveLog.Truncate(off)
		return fmt.Errorf("tsa archive: %w", err)
	}
	s.archiveEnd = off + int64(len(line))
	if k := len(s.archiveIdx); k == 0 || h.size > s.archiveIdx[k-1].size {
		s.archiveIdx = append(s.archiveIdx, archiveRef{size: h.size, off: off, n: len(line), key: key, ok: true})
		s.indexArchive(len(s.archiveIdx)-1, key)
	}
	a.head.Store(h.size)
	a.okAt.Store(time.Now().UnixNano())
	a.lastErr.Store(nil)
	return nil
}

// archiveForLocked — метки второй службы для пакета, чьи токены лежат в
// звеньях tokenLinks: для каждого — от каждой службы (по ключу подписи), чьи
// метки есть в журнале, самая ранняя метка над головой не раньше его звена,
// которая сходится с цепью и проходит проверку. Службу меняют, когда прежняя
// стала негодной (её корень не принимают, её ключ отозван): тогда POE даёт
// метка новой, и выбирает её аудитор. Голова дальше last (последнего звена
// пакета) — с доказательством продолжения от него. Строка, которая идёт в
// пакет впервые, проверяется; не сошлась — помечается и громко в журнал
// процесса, в пакет идёт следующая той же службы. Звать под chainMu
// (порядок: chainMu раньше archiveMu).
func (s *Store) archiveForLocked(tokenLinks []uint64, last uint64) ([]proof.ArchiveStamp, error) {
	if !s.archiveOn || len(tokenLinks) == 0 {
		return nil, nil
	}
	s.archiveMu.Lock()
	defer s.archiveMu.Unlock()
	if s.archiveLog == nil {
		return nil, nil // хранилище закрывается
	}
	var inter []*x509.Certificate
	if s.archiver != nil {
		inter = s.archiver.trust.Intermediates
	}
	var out []proof.ArchiveStamp
	seen := map[int64]bool{} // строки, уже взятые в пакет
	type pick struct {
		i   int
		rec archiveRecord
	}
	for _, l := range tokenLinks {
		// От каждой службы — её самая ранняя годная строка не раньше звена l:
		// поиск по строкам службы, не проход журнала на каждое звено.
		var picked []pick
		for _, k := range s.archiveKeyOrder {
			idx := s.archiveByKey[k]
			for j := sort.Search(len(idx), func(j int) bool { return s.archiveIdx[idx[j]].size >= l }); j < len(idx); j++ {
				ref := &s.archiveIdx[idx[j]]
				if ref.ok && seen[ref.off] {
					break // уже в пакете
				}
				rec, ok, err := s.archiveLineLocked(ref, inter)
				if err != nil {
					return nil, err
				}
				if ok {
					picked = append(picked, pick{idx[j], rec})
					break
				}
			}
		}
		slices.SortFunc(picked, func(a, b pick) int { return cmp.Compare(a.i, b.i) })
		for _, p := range picked {
			ref, rec := s.archiveIdx[p.i], p.rec
			if seen[ref.off] {
				continue
			}
			seen[ref.off] = true
			st := proof.ArchiveStamp{HeadSeq: rec.Size, Root: rec.Root, Token: rec.Token, Cert: rec.Cert}
			if rec.Size > last {
				pr, err := tlog.ProveTree(int64(rec.Size), int64(last), s.tree)
				if err != nil {
					return nil, err
				}
				for _, h := range pr {
					st.Proof = append(st.Proof, h[:])
				}
			}
			out = append(out, st)
		}
	}
	return out, nil
}

// indexArchive — строка i журнала (archiveIdx) в списке её службы.
func (s *Store) indexArchive(i int, key [32]byte) {
	if _, ok := s.archiveByKey[key]; !ok {
		s.archiveKeyOrder = append(s.archiveKeyOrder, key)
	}
	s.archiveByKey[key] = append(s.archiveByKey[key], i)
}

// archiveLineLocked читает строку ref и, когда она идёт в пакет впервые,
// сверяет: голова — с цепью, токен цел и заверяет её (tsa.Signed: доверие к
// службе с тех пор могли сменить, а проверит его аудитор), поле key называет
// ключ, которым токен подписан. Не сошлось — строка помечается негодной и
// громко в журнал процесса (ok = false). Звать под chainMu и archiveMu.
func (s *Store) archiveLineLocked(ref *archiveRef, inter []*x509.Certificate) (archiveRecord, bool, error) {
	if ref.bad {
		return archiveRecord{}, false, nil
	}
	rec, err := s.readArchiveLocked(*ref)
	if err != nil {
		return rec, false, err
	}
	if ref.ok {
		return rec, true, nil
	}
	root := [32]byte(rec.Root)
	err = s.tree.agreesLocked(rec.Size, root)
	if errors.Is(err, errTreeFile) {
		err = fmt.Errorf("its root is not the root of this chain at head %d: the line comes from another history of this store, or tree.hashes is damaged", rec.Size)
	}
	var signer *x509.Certificate
	if err == nil {
		signer, err = tsa.SignedBy(rec.Token, proof.HeadImprint(rec.Size, root), rec.signerCerts(inter)...)
	}
	if err == nil && sha256.Sum256(signer.RawSubjectPublicKeyInfo) != ref.key {
		err = errors.New("its key field does not name the key that signed its token: the line was changed")
	}
	if err != nil {
		s.log.Error("tsa archive: a line is not used", "head", rec.Size, "offset", ref.off, "err", err)
		ref.bad = true
		return rec, false, nil
	}
	ref.ok = true
	return rec, true, nil
}

// archiveFor — archiveForLocked под chainMu: для пакетов за окно и по
// источнику, которые собираются без него.
func (s *Store) archiveFor(tokenLinks []uint64, last uint64) ([]proof.ArchiveStamp, error) {
	if !s.archiveOn {
		return nil, nil
	}
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	return s.archiveForLocked(tokenLinks, last)
}

// archiveForStretch — метки второй службы для токенов основной в звеньях
// (lo, hi] — участка пакета за окно.
func (s *Store) archiveForStretch(lo, hi, last uint64) ([]proof.ArchiveStamp, error) {
	if !s.archiveOn {
		return nil, nil
	}
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	var links []uint64
	for _, t := range s.tokens {
		if l, ok := s.linkOfLocked(t.leaf); ok && l.seq > lo && l.seq <= hi {
			links = append(links, l.seq)
		}
	}
	return s.archiveForLocked(links, last)
}

// readArchiveLocked читает строку журнала ref. Звать под archiveMu.
func (s *Store) readArchiveLocked(ref archiveRef) (archiveRecord, error) {
	line := make([]byte, ref.n)
	if _, err := s.archiveLog.ReadAt(line, ref.off); err != nil {
		return archiveRecord{}, fmt.Errorf("tsa archive: %w", err)
	}
	var rec archiveRecord
	if err := json.Unmarshal(bytes.TrimSuffix(line, []byte("\n")), &rec); err != nil || rec.Size != ref.size || len(rec.Root) != 32 {
		return archiveRecord{}, fmt.Errorf("tsa archive: the line at offset %d changed under the store", ref.off)
	}
	return rec, nil
}

// ArchiveStatus — вторая служба в evidencestore status.
type ArchiveStatus struct {
	URL       string    `json:"url"`
	Head      uint64    `json:"head"`
	LastAt    time.Time `json:"last_at,omitzero"`
	Errors    uint64    `json:"errors"`
	LastError string    `json:"last_error,omitempty"`
}

func (s *Store) archiveStatus() *ArchiveStatus {
	a := s.archiver
	if a == nil {
		return nil
	}
	st := &ArchiveStatus{URL: a.url, Head: a.head.Load(), Errors: a.errors.Load()}
	if t := a.okAt.Load(); t != 0 {
		st.LastAt = time.Unix(0, t).UTC()
	}
	if e := a.lastErr.Load(); e != nil {
		st.LastError = *e
	}
	return st
}

// archiveLogSize — размер журнала для копии наружу: конец последней целой
// строки, уже на диске. ok = false — журнала нет.
func (s *Store) archiveLogSize() (int64, bool, error) {
	if s.archiveLog == nil {
		return 0, false, nil
	}
	s.archiveMu.Lock()
	defer s.archiveMu.Unlock()
	return s.archiveEnd, true, nil
}

// archiveRange — байты from…end журнала для копии: из открытого файла, как
// cosignRange. Журнал не открыт (второй службы нет) — по пути.
func (s *Store) archiveRange(from, end int64) ([]byte, error) {
	s.archiveMu.Lock()
	defer s.archiveMu.Unlock()
	if s.archiveLog == nil {
		return readRange(filepath.Join(s.cfg.DataDir, filepath.FromSlash(archiveFile)), from, end)
	}
	buf := make([]byte, end-from)
	if _, err := s.archiveLog.ReadAt(buf, from); err != nil {
		return nil, fmt.Errorf("replica: read %s: %w", archiveFile, err)
	}
	return buf, nil
}

func (s *Store) closeArchiveLog() error {
	if s.archiveLog == nil {
		return nil
	}
	err := s.archiveLog.Close()
	s.archiveLog = nil
	return err
}
