package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
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

const replicaStateFile = "replica.json"

type replicaState struct {
	Offsets map[string]int64 `json:"offsets"`
	Head    uint64           `json:"head"`
}

// replicaFiles — дописываемые файлы и сколько байт в каждом уже можно
// копировать: у цепи — прочитанное под замком цепи (только целые кадры), у
// журнала — подтверждённое fsync.
//
// ⚠ Порядок снимков — сначала цепь, потом журнал. Лист улики ложится в цепь
// только после fsync улики, поэтому всё, что знает снятая цепь, уже есть в
// снятом позже журнале. В обратном порядке между снимками могла прийти
// улика: цепь в копии знала бы её, а журнал нет, и восстановленное
// хранилище отказалось бы стартовать (ErrEvidenceLost).
func (s *Store) replicaFiles() (map[string]int64, error) {
	out := map[string]int64{}
	s.chainMu.Lock()
	entries, err := os.ReadDir(s.chainDir)
	if err != nil {
		s.chainMu.Unlock()
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if name != "chain.log" && !(strings.HasPrefix(name, "leaves_") && strings.HasSuffix(name, ".log")) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			s.chainMu.Unlock()
			return nil, err
		}
		out["chain/"+name] = fi.Size()
	}
	s.chainMu.Unlock()
	for _, seg := range s.evlog.Segments() {
		out["evidence/"+filepath.Base(seg.Path)] = seg.Size
	}
	return out, nil
}

func (s *Store) loadReplicaState(ctx context.Context, r ship.Remote) error {
	if s.replica != nil {
		return nil
	}
	st := &replicaState{Offsets: map[string]int64{}}
	data, err := os.ReadFile(filepath.Join(s.cfg.DataDir, replicaStateFile))
	switch {
	case err == nil:
		if err := json.Unmarshal(data, st); err != nil {
			return fmt.Errorf("replica state: %w", err)
		}
	case errors.Is(err, os.ErrNotExist):
		// Состояния нет (первый запуск или новая машина): докуда доехало,
		// узнаём у самой копии.
		files, _, err := listReplica(ctx, r)
		if err != nil {
			return err
		}
		for name, chunks := range files {
			if n := len(chunks); n > 0 {
				st.Offsets[name] = chunks[n-1].end
			}
		}
	default:
		return err
	}
	s.replica = st
	return nil
}

func (s *Store) saveReplicaState() error {
	data, _ := json.Marshal(s.replica)
	p := filepath.Join(s.cfg.DataDir, replicaStateFile)
	if err := os.WriteFile(p+".tmp", data, 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
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
	files, err := s.replicaFiles()
	if err != nil {
		return 0, err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var total int64
	for _, name := range names {
		size, from := files[name], s.replica.Offsets[name]
		if size < from {
			// Файл стал короче отправленного: так бывает, только если его
			// обрезали. Молча догонять нельзя — кусок в копии уже другой.
			return total, fmt.Errorf("replica: %s is %d bytes, %d already copied — file was truncated", name, size, from)
		}
		local := filepath.Join(s.cfg.DataDir, filepath.FromSlash(name))
		for from < size {
			end := min(size, from+replicaChunk)
			data, err := readRange(local, from, end)
			if err != nil {
				return total, err
			}
			if err := r.Put(ctx, chunkKey(name, from, end), data); err != nil {
				return total, err
			}
			total += end - from
			from = end
			s.replica.Offsets[name] = from
			if err := s.saveReplicaState(); err != nil {
				return total, err
			}
		}
	}
	st := s.Statement()
	if st.HeadSeq > s.replica.Head {
		data, _ := st.JSON()
		if err := r.Put(ctx, fmt.Sprintf("heads/%020d.json", st.HeadSeq), data); err != nil {
			return total, err
		}
		s.replica.Head = st.HeadSeq
		if err := s.saveReplicaState(); err != nil {
			return total, err
		}
	}
	return total, nil
}

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

// listReplica разбирает копию: куски по файлам (по порядку) и головы.
func listReplica(ctx context.Context, r ship.Remote) (map[string][]chunk, []string, error) {
	keys, err := r.List(ctx, "")
	if err != nil {
		return nil, nil, err
	}
	files := map[string][]chunk{}
	var heads []string
	for _, k := range keys {
		if strings.HasPrefix(k, "heads/") {
			heads = append(heads, k)
			continue
		}
		dir, base := path.Split(k)
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
}

// RestoreReplica собирает журнал улик и цепь из копии в пустой каталог
// данных и сверяет цепь с последней подписанной головой копии (по
// закреплённому ключу хранилища). keyring.dat, корни и sign.key в копии нет:
// их кладут из резерва ключей отдельно.
func RestoreReplica(ctx context.Context, r ship.Remote, dataDir string, pinned ed25519.PublicKey) (RestoreReport, error) {
	var rep RestoreReport
	for _, sub := range []string{"evidence", "chain"} {
		if entries, err := os.ReadDir(filepath.Join(dataDir, sub)); err == nil && len(entries) > 0 {
			return rep, fmt.Errorf("replica restore: %s is not empty — refusing to overwrite", filepath.Join(dataDir, sub))
		}
	}
	files, heads, err := listReplica(ctx, r)
	if err != nil {
		return rep, err
	}
	if len(heads) == 0 {
		return rep, errors.New("replica restore: no signed head in the copy")
	}
	for name, chunks := range files {
		var data []byte
		for i, c := range chunks {
			if (i == 0 && c.start != 0) || (i > 0 && c.start != chunks[i-1].end) {
				return rep, fmt.Errorf("replica restore: %s: hole at %d", name, c.start)
			}
			b, err := r.Get(ctx, c.key)
			if err != nil {
				return rep, err
			}
			if int64(len(b)) != c.end-c.start {
				return rep, fmt.Errorf("replica restore: %s is %d bytes, name says %d", c.key, len(b), c.end-c.start)
			}
			data = append(data, b...)
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
	stData, err := r.Get(ctx, heads[len(heads)-1])
	if err != nil {
		return rep, err
	}
	st, err := auditchain.ParseStatement(stData)
	if err != nil {
		return rep, err
	}
	if err := auditchain.VerifyStatement(st, pinned); err != nil {
		return rep, fmt.Errorf("replica restore: last head in the copy: %w", err)
	}
	links, err := auditchain.ReadChain(filepath.Join(dataDir, "chain"))
	if err != nil {
		return rep, err
	}
	if uint64(len(links)) < st.HeadSeq {
		return rep, fmt.Errorf("replica restore: copy holds %d links, signed head is %d — copy is incomplete", len(links), st.HeadSeq)
	}
	head, err := auditchain.Verify(links[:st.HeadSeq], nil)
	if err != nil {
		return rep, fmt.Errorf("replica restore: %w", err)
	}
	if auditchain.EncodeHash(head.Hash) != st.HeadHash {
		return rep, errors.New("replica restore: chain in the copy does not match its signed head — copy was altered")
	}
	rep.HeadSeq = st.HeadSeq
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
