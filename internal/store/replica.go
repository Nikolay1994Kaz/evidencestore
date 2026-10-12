package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"evidencestore/internal/auditchain"
	"evidencestore/internal/ship"
)

// Копия наружу (S3 или каталог). Уезжают только дописываемые файлы, кусками
// по смещению, как в Litestream:
//
//	evidence/seg_….log/<начало>-<конец>   журнал улик (только подтверждённое fsync)
//	chain/chain.log/<начало>-<конец>      звенья цепи
//	chain/leaves_….log/<начало>-<конец>   листья цепи
//	heads/<номер головы>.json             подписанная голова на момент копии
//
// Объекты неизменяемы и не удаляются никогда: копия улик тоже улика.
// keyring.dat, корни и ключ подписи не уезжают: в копии только шифротекст и
// открытые доказательства, стирание по-прежнему сводится к одному ключу.
// Отставание копии (RPO) — до replica.every.
//
// Докуда доехала копия, знает сама копия: первый проход после запуска берёт
// смещения из её листинга, дальше они живут в памяти. Своего файла
// состояния нет: файл, откатившийся после сбоя, слал бы куски внахлёст.
// Тот же первый проход сверяет с data_dir последний кусок новейших файлов
// копии: копию, которая не начало файлов data_dir, хранилище не дописывает
// (Z-09) — data_dir потерял уже скопированное (диск соврал про fsync) или
// копию писал не он, и байты с её смещений с её кусками не стыковались бы.
//
// ПОКОЛЕНИЯ. Хранилище, поднятое из копии, пишет её дальше не в прежние
// ключи, а новым поколением в gen/<номер>/, целиком с нуля (Z-08). Подъём
// отрезает хвост прерванного прохода копии, который не заверен подписанной
// головой (Z-07), а старт — оборванную запись журнала улик; с отрезанного
// места поднятое хранилище пишет уже другие байты, а в копии там лежит
// мёртвый хвост. Номер поколения подъём кладёт в data_dir
// (replica-generation); прежние поколения остаются как были. Подъём берёт
// новейшее поколение с подписанной головой: поколение, чей первый проход не
// дошёл до головы, пропускается.

type replicaState struct {
	Prefix  string // поколение, в которое пишет хранилище: "" (первое) или gen/<номер>/
	Offsets map[string]int64
	Head    uint64
}

// replicaSnapshot — что можно копировать сейчас: размер каждого
// дописываемого файла и подписанная голова, снятые согласованно.
type replicaSnapshot struct {
	sizes map[string]int64
	head  auditchain.Statement
}

// replicaFiles снимает размеры файлов: у цепи — под замком цепи (только целые
// кадры) вместе с подписанной головой, у журнала — подтверждённое fsync.
//
// ⚠ Порядок снимков — сначала цепь, потом журнал. Лист улики ложится в цепь
// только после fsync улики, поэтому всё, что знает снятая цепь, уже есть в
// снятом позже журнале. Голова подписывается под тем же замком, что
// снимаются размеры цепи: иначе тик успевал добавить звено, и голова в копии
// указывала на звено, которого в ней нет.
func (s *Store) replicaFiles() (replicaSnapshot, error) {
	snap := replicaSnapshot{sizes: map[string]int64{}}
	s.chainMu.Lock()
	entries, err := os.ReadDir(s.chainDir)
	if err != nil {
		s.chainMu.Unlock()
		return snap, err
	}
	for _, e := range entries {
		name := e.Name()
		if name != "chain.log" && !(strings.HasPrefix(name, "leaves_") && strings.HasSuffix(name, ".log")) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			s.chainMu.Unlock()
			return snap, err
		}
		snap.sizes["chain/"+name] = fi.Size()
	}
	snap.head = s.signer.Sign(s.chain.Head(), len(s.links), s.nowTime().Unix())
	s.chainMu.Unlock()
	for _, seg := range s.evlog.Segments() {
		snap.sizes["evidence/"+filepath.Base(seg.Path)] = seg.Size
	}
	return snap, nil
}

// loadReplicaState узнаёт у копии, докуда она доехала: конец последнего
// куска каждого файла и последняя голова.
func (s *Store) loadReplicaState(ctx context.Context, r ship.Remote) error {
	if s.replica != nil {
		return nil
	}
	gen, err := readGeneration(s.cfg.DataDir)
	if err != nil {
		return err
	}
	prefix := genPrefix(gen)
	files, heads, err := listReplica(ctx, r, prefix)
	if err != nil {
		return err
	}
	if err := s.checkReplicaTail(ctx, r, files); err != nil {
		return err
	}
	st := &replicaState{Prefix: prefix, Offsets: map[string]int64{}}
	for name, chunks := range files {
		for _, c := range chunks {
			st.Offsets[name] = max(st.Offsets[name], c.end)
		}
	}
	if n := len(heads); n > 0 {
		st.Head, _ = headSeqOf(heads[n-1])
	}
	s.replica = st
	return nil
}

// ErrReplicaDiverged — копия не начало файлов data_dir: дописывать её нельзя.
var ErrReplicaDiverged = errors.New("replica: the copy is not where data_dir left it")

const divergedHint = "data_dir lost data after it was copied (a disk that lied about fsync?) or did not write this copy: restore from the copy into an empty data_dir, or point replica.url at a new location (the old copy stays as evidence)"

// checkReplicaTail сверяет с data_dir последний кусок новейшего файла
// каждого вида в копии. Разойтись файлы могли только в хвосте: закрытые
// сегменты не меняются.
func (s *Store) checkReplicaTail(ctx context.Context, r ship.Remote, files map[string][]chunk) error {
	newest := map[string]string{}
	for name := range files {
		kind := name
		if strings.HasPrefix(name, "evidence/") {
			kind = "evidence/"
		} else if strings.HasPrefix(name, "chain/leaves_") {
			kind = "chain/leaves_"
		}
		newest[kind] = max(newest[kind], name)
	}
	for _, name := range newest {
		last := files[name][0]
		for _, c := range files[name] {
			if c.end > last.end {
				last = c
			}
		}
		copied, err := r.Get(ctx, last.key)
		if err != nil {
			return err
		}
		local, err := readRange(filepath.Join(s.cfg.DataDir, filepath.FromSlash(name)), last.start, last.end)
		if err != nil || !bytes.Equal(local, copied) {
			return fmt.Errorf("%w: its %s holds bytes %d-%d that data_dir lacks or has otherwise; %s", ErrReplicaDiverged, name, last.start, last.end, divergedHint)
		}
	}
	return nil
}

// headSeqOf — номер головы из имени …heads/<номер>.json.
func headSeqOf(key string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSuffix(path.Base(key), ".json"), 10, 64)
}

// genPrefix — где в копии лежит поколение gen: первое — в корне, следующие
// — в gen/<номер>/.
func genPrefix(gen uint64) string {
	if gen == 0 {
		return ""
	}
	return fmt.Sprintf("gen/%020d/", gen)
}

// generationFile — номер поколения копии, в которое пишет хранилище,
// поднятое из копии (кладёт RestoreReplica). Нет файла — первое поколение.
const generationFile = "replica-generation"

func readGeneration(dataDir string) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, generationFile))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	gen, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("replica: bad %s: %w", generationFile, err)
	}
	return gen, nil
}

// generations — поколения копии: новейшее, в котором есть подписанная
// голова, и первый свободный номер.
func generations(keys []string) (newest, free uint64, ok bool) {
	for _, k := range keys {
		gen, rel := uint64(0), k
		if rest, found := strings.CutPrefix(k, "gen/"); found {
			n, after, _ := strings.Cut(rest, "/")
			g, err := strconv.ParseUint(n, 10, 64)
			if err != nil || g == 0 {
				continue // чужие объекты в бакете не наши
			}
			gen, rel = g, after
		}
		free = max(free, gen+1)
		if strings.HasPrefix(rel, "heads/") && (!ok || gen > newest) {
			newest, ok = gen, true
		}
	}
	return newest, free, ok
}

// ShipOnce дотягивает копию: новые байты каждого файла и подписанную
// голову. Отдаёт, сколько байт уехало.
func (s *Store) ShipOnce(ctx context.Context, r ship.Remote) (_ int64, err error) {
	defer func() {
		if err != nil {
			s.replicaErrors.Add(1)
		} else {
			s.replicaOK.Store(time.Now().UnixNano())
		}
	}()
	s.replicaMu.Lock()
	defer s.replicaMu.Unlock()
	if err := s.loadReplicaState(ctx, r); err != nil {
		return 0, err
	}
	snap, err := s.replicaFiles()
	if err != nil {
		return 0, err
	}
	// Журнал улик уезжает раньше цепи: прерванный проход не оставляет в копии
	// цепь, которая знает улики, которых в копии нет (восстановленное
	// хранилище отказалось бы стартовать с ErrEvidenceLost).
	names := make([]string, 0, len(snap.sizes))
	for n := range snap.sizes {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		ei, ej := strings.HasPrefix(names[i], "evidence/"), strings.HasPrefix(names[j], "evidence/")
		if ei != ej {
			return ei
		}
		return names[i] < names[j]
	})
	var total int64
	for _, name := range names {
		size, from := snap.sizes[name], s.replica.Offsets[name]
		if size < from {
			// Файл стал короче отправленного: так бывает, только если его
			// обрезали. Молча догонять нельзя — кусок в копии уже другой.
			return total, fmt.Errorf("%w: %s is %d bytes, %d already copied — file was truncated; %s", ErrReplicaDiverged, name, size, from, divergedHint)
		}
		local := filepath.Join(s.cfg.DataDir, filepath.FromSlash(name))
		for from < size {
			end := min(size, from+s.replicaChunk)
			data, err := readRange(local, from, end)
			if err != nil {
				return total, err
			}
			if err := r.Put(ctx, s.replica.Prefix+chunkKey(name, from, end), data); err != nil {
				return total, err
			}
			total += end - from
			from = end
			s.replica.Offsets[name] = from
		}
	}
	if st := snap.head; st.HeadSeq > s.replica.Head {
		data, _ := st.JSON()
		if err := r.Put(ctx, s.replica.Prefix+fmt.Sprintf("heads/%020d.json", st.HeadSeq), data); err != nil {
			return total, err
		}
		s.replica.Head = st.HeadSeq
	}
	return total, nil
}

// replicaChunk — предел куска копии (Options.replicaChunk в тестах).
const replicaChunk = 16 << 20

func chunkKey(name string, from, end int64) string {
	return fmt.Sprintf("%s/%020d-%020d", name, from, end)
}

func readRange(p string, from, end int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, end-from)
	if _, err := f.ReadAt(buf, from); err != nil {
		return nil, fmt.Errorf("replica: read %s: %w", p, err)
	}
	return buf, nil
}

type chunk struct {
	key        string
	start, end int64
}

// listReplica разбирает поколение копии под prefix: куски по файлам (по
// порядку) и головы.
func listReplica(ctx context.Context, r ship.Remote, prefix string) (map[string][]chunk, []string, error) {
	keys, err := r.List(ctx, prefix)
	if err != nil {
		return nil, nil, err
	}
	return parseReplica(keys, prefix)
}

// parseReplica разбирает ключи поколения prefix: имена файлов — без prefix,
// ключи кусков и голов — полные. Ключи других поколений пропускаются (у
// первого поколения — как чужие: не под evidence/, chain/ или heads/).
func parseReplica(keys []string, prefix string) (map[string][]chunk, []string, error) {
	files := map[string][]chunk{}
	var heads []string
	for _, k := range keys {
		rel, ok := strings.CutPrefix(k, prefix)
		if !ok {
			continue
		}
		if strings.HasPrefix(rel, "heads/") {
			heads = append(heads, k)
			continue
		}
		dir, base := path.Split(rel)
		se := strings.SplitN(base, "-", 2)
		if len(se) != 2 || (!strings.HasPrefix(dir, "evidence/") && !strings.HasPrefix(dir, "chain/")) {
			continue // чужие объекты в бакете не наши
		}
		start, err1 := strconv.ParseInt(se[0], 10, 64)
		end, err2 := strconv.ParseInt(se[1], 10, 64)
		if err1 != nil || err2 != nil || end <= start {
			return nil, nil, fmt.Errorf("replica: bad chunk name %s", k)
		}
		name := strings.TrimSuffix(dir, "/")
		files[name] = append(files[name], chunk{key: k, start: start, end: end})
	}
	for _, cs := range files {
		sort.Slice(cs, func(i, j int) bool { return cs[i].start < cs[j].start })
	}
	sort.Strings(heads)
	return files, heads, nil
}

// RestoreReport — что собрано из копии.
type RestoreReport struct {
	Files   int
	Bytes   int64
	HeadSeq uint64
	// Generation — поколение копии, из которого собрано; NextGeneration —
	// поколение, которым поднятое хранилище пишет копию дальше.
	Generation, NextGeneration uint64
}

// RestoreReplica собирает журнал улик и цепь из копии в пустой каталог
// данных и сверяет цепь с последней подписанной головой копии (по
// закреплённому ключу хранилища). keyring.dat, корни и sign.key в копии нет:
// их кладут из резерва ключей отдельно.
func RestoreReplica(ctx context.Context, r ship.Remote, dataDir string, pinned ed25519.PublicKey) (RestoreReport, error) {
	var rep RestoreReport
	lock, err := lockDataDir(dataDir)
	if err != nil {
		return rep, err
	}
	defer lock.Close()
	for _, sub := range []string{"evidence", "chain"} {
		if entries, err := os.ReadDir(filepath.Join(dataDir, sub)); err == nil && len(entries) > 0 {
			return rep, fmt.Errorf("replica restore: %s is not empty — refusing to overwrite", filepath.Join(dataDir, sub))
		}
	}
	keys, err := r.List(ctx, "")
	if err != nil {
		return rep, err
	}
	gen, free, ok := generations(keys)
	if !ok {
		return rep, errors.New("replica restore: no signed head in the copy")
	}
	files, heads, err := parseReplica(keys, genPrefix(gen))
	if err != nil {
		return rep, err
	}
	for name, chunks := range files {
		var data []byte
		for _, c := range chunks {
			// Куски внахлёст бывают (копия прежней версии повторяла кусок с
			// откатившегося смещения): общая часть обязана совпасть байт в
			// байт, дописывается только новое.
			have := int64(len(data))
			if c.start > have {
				return rep, fmt.Errorf("replica restore: %s: hole at %d", name, have)
			}
			b, err := r.Get(ctx, c.key)
			if err != nil {
				return rep, err
			}
			if int64(len(b)) != c.end-c.start {
				return rep, fmt.Errorf("replica restore: %s is %d bytes, name says %d", c.key, len(b), c.end-c.start)
			}
			overlap := min(have, c.end) - c.start
			if !bytes.Equal(data[c.start:c.start+overlap], b[:overlap]) {
				return rep, fmt.Errorf("replica restore: %s: chunk %s disagrees with the bytes already in the copy", name, c.key)
			}
			data = append(data, b[overlap:]...)
		}
		dst := filepath.Join(dataDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return rep, err
		}
		if err := writeDurable(dst, data); err != nil {
			return rep, err
		}
		rep.Files++
		rep.Bytes += int64(len(data))
	}
	links, err := auditchain.ReadChain(filepath.Join(dataDir, "chain"))
	if err != nil {
		return rep, err
	}
	// Голова — последняя из тех, чьё звено есть в копии: голова новее
	// звеньев копии (кусок цепи не доехал) не повод отказывать, если есть
	// подписанная голова пораньше.
	var st auditchain.Statement
	for i := len(heads) - 1; i >= 0; i-- {
		if seq, err := headSeqOf(heads[i]); err == nil && seq <= uint64(len(links)) {
			stData, err := r.Get(ctx, heads[i])
			if err != nil {
				return rep, err
			}
			if st, err = auditchain.ParseStatement(stData); err != nil {
				return rep, err
			}
			break
		}
	}
	if st.HeadSeq == 0 {
		return rep, fmt.Errorf("replica restore: copy holds %d links, every signed head is newer — copy is incomplete", len(links))
	}
	if err := auditchain.VerifyStatement(st, pinned); err != nil {
		return rep, fmt.Errorf("replica restore: head %d in the copy: %w", st.HeadSeq, err)
	}
	head, err := auditchain.Verify(links[:st.HeadSeq], nil)
	if err != nil {
		return rep, fmt.Errorf("replica restore: %w", err)
	}
	if auditchain.EncodeHash(head.Hash) != st.HeadHash {
		return rep, errors.New("replica restore: chain in the copy does not match its signed head — copy was altered")
	}
	// Цепь — ровно по подписанной голове: хвост прерванного прохода копии
	// голова не заверяет (Z-07). Улики после неё подъём досчитает в цепь по
	// журналу улик.
	if err := auditchain.TrimToHead(filepath.Join(dataDir, "chain"), st.HeadSeq); err != nil {
		return rep, fmt.Errorf("replica restore: %w", err)
	}
	// Дальше копию пишет новое поколение (Z-08).
	if err := writeAtomic(filepath.Join(dataDir, generationFile), []byte(strconv.FormatUint(free, 10)+"\n")); err != nil {
		return rep, err
	}
	rep.HeadSeq, rep.Generation, rep.NextGeneration = st.HeadSeq, gen, free
	return rep, nil
}

func writeDurable(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	return errors.Join(werr, serr, f.Close())
}
