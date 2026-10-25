package store

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Proof собирает пакет доказательств по улике (source, seq). withDEK —
// приложить ключ этой записи, чтобы проверяющий вскрыл тело; ключ месяца
// при этом не выдаётся.
//
// Если улика ещё не накрыта звеном, хвост цепи сворачивается сейчас же.
// Метки TSA в пакет кладутся те, что уже есть: нужна свежая верхняя
// граница — сначала Stamp.
func (s *Store) Proof(source string, seq uint64, withDEK bool) (proof.Bundle, error) {
	s.mu.Lock()
	st, ok := s.sources[source]
	var pos uint64
	if ok {
		pos = st.seqs.get(seq)
	}
	s.mu.Unlock()
	if pos == 0 {
		return proof.Bundle{}, fmt.Errorf("%w: %s/%d", ErrNotFound, source, seq)
	}
	data, err := s.evlog.Read(pos)
	if err != nil {
		return proof.Bundle{}, err
	}
	b := proof.Bundle{Version: proof.Version, Evidence: data}

	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	if err := s.flushLocked(); err != nil {
		return proof.Bundle{}, err
	}
	if pos > uint64(len(s.evLeaf)) || s.evLeaf[pos-1] == 0 {
		return proof.Bundle{}, fmt.Errorf("store: evidence %d is not in the chain yet", pos)
	}
	leaf := s.evLeaf[pos-1] - 1
	if b.Inclusion, err = s.inclusionLocked(leaf); err != nil {
		return proof.Bundle{}, err
	}
	n := b.Inclusion.LinkSeq
	from := n

	// T2: первая метка над головой не раньше звена улики.
	for _, t := range s.tokens {
		if t.head >= n {
			token, err := s.leafPayloadLocked(t.leaf)
			if err != nil {
				return proof.Bundle{}, err
			}
			b.Upper = &proof.Upper{HeadSeq: t.head, Token: token}
			break
		}
	}
	// Журнал гейтвея: вердикт при приёме и контрольная точка после записи.
	if b.Gateway, err = s.gatewayProofLocked(source, pos); err != nil {
		return proof.Bundle{}, err
	}

	// T1: последняя метка, лежащая в звене раньше звена улики.
	for i := len(s.tokens) - 1; i >= 0; i-- {
		t := s.tokens[i]
		link, ok := s.linkOfLocked(t.leaf)
		if !ok || link.seq >= n {
			continue
		}
		inc, err := s.inclusionLocked(t.leaf)
		if err != nil {
			return proof.Bundle{}, err
		}
		b.Lower = &proof.Lower{Inclusion: inc}
		from = min(from, t.head) // звено, которое заверяет T1, тоже нужно проверяющему
		break
	}

	// Пакет кончается головой T2: дальше проверке ничего не нужно, а звенья
	// после неё растили бы пакет с каждым тиком без предела (P-06). Вердикт и
	// контрольная точка гейтвея могут лечь в звенья позже T2 — тогда пакет
	// доходит до последнего из них. Без T2 — до текущей головы.
	to := s.chain.Head().Seq
	if b.Upper != nil {
		to = b.Upper.HeadSeq
		if g := b.Gateway; g != nil {
			to = max(to, g.Entry.LinkSeq)
			if g.Checkpoint != nil {
				to = max(to, g.Checkpoint.LinkSeq)
			}
		}
	}
	links, err := auditchain.ReadLinks(s.chainDir, from, to)
	if err != nil {
		return proof.Bundle{}, err
	}
	for _, l := range links {
		b.Links = append(b.Links, proof.FromLink(l))
	}
	// Заявление — о голове, которой кончается пакет; подписано при выдаче.
	last := links[len(links)-1]
	b.Statement = s.signer.Sign(auditchain.Head{Seq: last.Seq, Hash: auditchain.Hash(last)}, int(last.Seq), s.nowTime().Unix())

	if withDEK {
		sealed, err := evidence.Unmarshal(data)
		if err != nil {
			return proof.Bundle{}, err
		}
		dek, err := s.keys.UnwrapDEK(sealed.Envelope)
		switch {
		case err == nil:
			b.DEK = dek
		case errors.Is(err, keyring.ErrKeyDestroyed), errors.Is(err, keyring.ErrKeyPending):
			// Стёрто или ждёт уничтожения: пакет всё равно доказывает
			// существование и неизменность, только без тела.
		default:
			return proof.Bundle{}, err
		}
	}
	return b, nil
}

// inclusionLocked — лист с номером leaf и путь до корня его звена.
func (s *Store) inclusionLocked(leaf uint64) (proof.Inclusion, error) {
	link, ok := s.linkOfLocked(leaf)
	if !ok {
		return proof.Inclusion{}, fmt.Errorf("store: leaf %d is not linked", leaf)
	}
	leaves, err := auditchain.ReadLeaves(s.chainDir, link.first, int(link.count))
	if err != nil {
		return proof.Inclusion{}, err
	}
	idx := int(leaf - link.first)
	path, err := auditchain.MerkleProof(leaves, idx)
	if err != nil {
		return proof.Inclusion{}, err
	}
	inc := proof.Inclusion{Leaf: proof.FromLeaf(leaves[idx]), LinkSeq: link.seq}
	for _, p := range path {
		inc.Path = append(inc.Path, proof.Step{Hash: p.Hash[:], Left: p.SiblingLeft})
	}
	return inc, nil
}

// leafPayloadLocked читает предмет листа с диска (цепь уже свёрнута).
func (s *Store) leafPayloadLocked(leaf uint64) ([]byte, error) {
	leaves, err := auditchain.ReadLeaves(s.chainDir, leaf, 1)
	if err != nil {
		return nil, err
	}
	return leaves[0].Payload, nil
}

// SourceStatus — состояние источника для оператора.
type SourceStatus struct {
	Name     string    `json:"name"`
	Known    bool      `json:"in_registry"`
	Disabled bool      `json:"disabled"`
	Records  uint64    `json:"records"`
	MaxSeq   uint64    `json:"max_seq"`
	LastAt   time.Time `json:"last_at"`
	Silent   bool      `json:"silent"`
	// Epoch — эпоха сборщика, закреплённая за источником (epoch.go).
	Epoch string `json:"collector_epoch,omitempty"`
}

// Status — сводка для оператора.
type Status struct {
	Records    uint64         `json:"records"`
	HeadSeq    uint64         `json:"head_seq"`
	HeadHash   string         `json:"head_hash"`
	Leaves     uint64         `json:"leaves"`
	Stamps     int            `json:"tsa_stamps"`
	LastStamp  time.Time      `json:"last_stamp,omitempty"`
	StampedTo  uint64         `json:"stamped_head"`
	PublicKey  string         `json:"public_key"`
	Sources    []SourceStatus `json:"sources"`
	LogFailure string         `json:"log_failure,omitempty"`
	// ChainFailure — цепь защёлкнута ошибкой записи (входит и в LogFailure:
	// приём отказывает так же).
	ChainFailure string `json:"chain_failure,omitempty"`
	// KeyringBackupPending — последняя запись keyring.dat не дошла до
	// резерва (keys.backup_dir); Confirm повторяет копию раз в минуту.
	KeyringBackupPending bool `json:"keyring_backup_pending,omitempty"`
	// OrphanRoots — корни, которых не знает keyring.dat: уничтожение не
	// окончательно, пока оператор их не уничтожит.
	OrphanRoots []string `json:"orphan_roots,omitempty"`
	// RootsUnreachable — каталоги корней не перечисляются (зеркало на
	// упавшей машине): сирот не видно, уничтожение не окончательно.
	RootsUnreachable string `json:"roots_unreachable,omitempty"`
}

func (s *Store) Status() Status {
	var out Status
	s.mu.Lock()
	for name, st := range s.sources {
		out.Sources = append(out.Sources, SourceStatus{
			Name: name, Known: st.known, Disabled: st.cfg.Disabled, Records: st.count,
			MaxSeq: st.maxSeq, LastAt: st.lastAt.UTC(), Silent: st.silent, Epoch: st.epoch,
		})
		out.Records += st.count
	}
	s.mu.Unlock()
	sort.Slice(out.Sources, func(i, j int) bool { return out.Sources[i].Name < out.Sources[j].Name })
	s.chainMu.Lock()
	h := s.chain.Head()
	out.HeadSeq, out.HeadHash, out.Leaves = h.Seq, auditchain.EncodeHash(h.Hash), s.nextLeaf
	out.Stamps, out.StampedTo = len(s.tokens), s.lastStamped
	if len(s.tokens) > 0 {
		out.LastStamp = s.tokens[len(s.tokens)-1].gen
	}
	s.chainMu.Unlock()
	out.PublicKey = s.signer.PublicKeyString()
	if err := s.Healthy(); err != nil {
		out.LogFailure = err.Error()
	}
	if err := s.chain.Failed(); err != nil {
		out.ChainFailure = err.Error()
	}
	out.KeyringBackupPending = s.keys.BackupPending()
	if orphans, err := s.keys.OrphanRoots(); err != nil {
		out.RootsUnreachable = err.Error()
	} else {
		out.OrphanRoots = orphans
	}
	return out
}
