package store

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
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
	return s.ProofTo(source, seq, withDEK, 0)
}

// ErrLabelErased — запись с меткой субъекта из месяца, чей ключ уничтожен или
// ждёт уничтожения: пакет одной улики показал бы её заголовок, а с ним метку, и
// метка, выданная до стирания, нашла бы по нему клиента (P-80).
var ErrLabelErased = errors.New("store: the record carries a subject label, and its month key is destroyed or awaits destruction")

// ProofTo — то же, но пакет доходит не меньше чем до головы toHead: до той,
// что видел свидетель, когда она позже конца пакета (esverify -heads). Запись с
// меткой из месяца с закрытым ключом не выдаётся (ErrLabelErased); выдать её
// заголовок, когда он нужен (спор об обещании сборщика), — ProofShowingLabel.
func (s *Store) ProofTo(source string, seq uint64, withDEK bool, toHead uint64) (proof.Bundle, error) {
	return s.proofTo(source, seq, withDEK, toHead, false)
}

// ProofShowingLabel — пакет одной улики и для записи с меткой из месяца с
// закрытым ключом: по явной просьбе оператора (proof -show-label).
func (s *Store) ProofShowingLabel(source string, seq uint64, withDEK bool, toHead uint64) (proof.Bundle, error) {
	return s.proofTo(source, seq, withDEK, toHead, true)
}

func (s *Store) proofTo(source string, seq uint64, withDEK bool, toHead uint64, showLabel bool) (proof.Bundle, error) {
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
	// labelled — месяц записи с меткой: её пакет выдаётся, только пока ключ
	// месяца жив (P-80). Проверка одна, в конце выдачи: ключ могли закрыть,
	// пока пакет собирался (P-86).
	var labelled string
	if !showLabel {
		sealed, err := evidence.Unmarshal(data)
		if err != nil {
			return proof.Bundle{}, err
		}
		if !sealed.Subject.IsZero() {
			labelled = sealed.Scope()
		}
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
	var upperLeaf proof.Inclusion
	for _, t := range s.tokens {
		if t.head >= n {
			token, err := s.leafPayloadLocked(t.leaf)
			if err != nil {
				return proof.Bundle{}, err
			}
			b.Upper = &proof.Upper{HeadSeq: t.head, Token: token}
			if upperLeaf, err = s.inclusionLocked(t.leaf); err != nil {
				return proof.Bundle{}, err
			}
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
		// Листья звеньев от головы под T1 до звена улики: по ним проверяющий
		// находит каждую метку перед уликой (сверка обещания по меткам).
		if b.Stretch, err = s.stretchLocked(t.head, n); err != nil {
			return proof.Bundle{}, err
		}
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
	if toHead > to {
		if head := s.chain.Head().Seq; toHead > head {
			return proof.Bundle{}, fmt.Errorf("store: head %d is not in the chain yet: the head is %d", toHead, head)
		}
		to = toHead
	}
	// Лист токена T2 — где лежит токен (proof.revoked): по нему метку
	// отозванного по компрометации сертификата спасает поздняя метка второй
	// службы или подпись свидетеля над головой его звена. Пакет доходит до
	// этого звена, только если есть то или другое или пакет и так туда
	// доходит: иначе лист нечем было бы подкрепить.
	if b.Upper != nil && (s.archiveOn || len(s.cosigners) > 0 || to >= upperLeaf.LinkSeq) {
		b.Upper.Inclusion = &upperLeaf
		to = max(to, upperLeaf.LinkSeq)
	}
	links, err := auditchain.ReadLinks(s.chainDir, from, to)
	if err != nil {
		return proof.Bundle{}, err
	}
	for _, l := range links {
		b.Links = append(b.Links, proof.FromLink(l))
	}
	// Голова — та, которой кончается пакет: граница дерева звеньев перед
	// первым звеном и контрольная точка на последнем, подписанная при выдаче.
	if b.Frontier, b.Checkpoint, err = s.bundleHeadLocked(links); err != nil {
		return proof.Bundle{}, err
	}
	// Подписи свидетелей C2SP: голова не раньше звена улики — и не раньше
	// звена токена T2: подпись над ней — POE для T2, если сертификат службы
	// отзовут по компрометации (proof.revoked). Хранилище отдаёт свидетелям
	// голову звена каждого токена, так что обычно это она и есть.
	if b.Cosignatures, err = s.cosignaturesForLocked(links[0].Seq, links[len(links)-1].Seq, n); err != nil {
		return proof.Bundle{}, err
	}
	if b.Upper != nil && b.Upper.Inclusion != nil {
		more, err := s.cosignaturesForLocked(links[0].Seq, links[len(links)-1].Seq, b.Upper.Inclusion.LinkSeq)
		if err != nil {
			return proof.Bundle{}, err
		}
		for _, c := range more {
			if !slices.ContainsFunc(b.Cosignatures, func(o proof.Cosignature) bool { return o.Name == c.Name && bytes.Equal(o.Sig, c.Sig) }) {
				b.Cosignatures = append(b.Cosignatures, c)
			}
		}
	}
	// Метки второй службы над головами не раньше токенов T1 и T2.
	var tokens []uint64
	if b.Lower != nil {
		tokens = append(tokens, b.Lower.Inclusion.LinkSeq)
	}
	if b.Upper != nil && b.Upper.Inclusion != nil {
		tokens = append(tokens, b.Upper.Inclusion.LinkSeq)
	}
	if b.Archive, err = s.archiveForLocked(tokens, links[len(links)-1].Seq); err != nil {
		return proof.Bundle{}, err
	}
	b.Seal = s.bundleSeal()

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
	if labelled != "" {
		if err := s.recheckOpen([]string{labelled}); errors.Is(err, ErrReissue) {
			return proof.Bundle{}, s.labelErased(source, seq)
		} else if err != nil {
			return proof.Bundle{}, err
		}
	}
	return b, nil
}

// labelErased — отказ пакету одной улики для записи с меткой из месяца с
// закрытым ключом. Совет взять пакет за окно — только когда у хранилища есть
// TSA: без меток окна не собрать (E3-02).
func (s *Store) labelErased(source string, seq uint64) error {
	alt := "a one-source bundle over a window around it proves the record as a leaf, without the header; "
	if s.tsaURL == "" && s.tsaLocal == nil {
		alt = ""
	}
	return fmt.Errorf("%w: %s/%d: a single-record bundle shows the record header, the label in it, and a label handed out before the erasure would find the client by it; %sif the header must be shown (a dispute over the collector's promise), ask with -show-label", ErrLabelErased, source, seq, alt)
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
	// LastContact — последнее обращение сборщика, пропущенное Admit (с
	// запуска хранилища); ContactLost — идёт эпизод «сборщик пропал»
	// (contact.go).
	LastContact time.Time `json:"last_contact"`
	ContactLost bool      `json:"contact_lost"`
}

// Status — сводка для оператора.
type Status struct {
	Records   uint64    `json:"records"`
	HeadSeq   uint64    `json:"head_seq"`
	HeadHash  string    `json:"head_hash"`
	Leaves    uint64    `json:"leaves"`
	Stamps    int       `json:"tsa_stamps"`
	LastStamp time.Time `json:"last_stamp,omitempty"`
	StampedTo uint64    `json:"stamped_head"`
	PublicKey string    `json:"public_key"`
	// LogKey — ключ проверки хранилища в виде vkey C2SP (имя — его
	// происхождение, тип 0x01): его просит свидетель другого проекта.
	LogKey     string         `json:"log_vkey"`
	Sources    []SourceStatus `json:"sources"`
	LogFailure string         `json:"log_failure,omitempty"`
	// ChainFailure — цепь защёлкнута ошибкой записи (входит и в LogFailure:
	// приём отказывает так же).
	ChainFailure string `json:"chain_failure,omitempty"`
	// KeyringBackupPending — последняя запись keyring.dat не дошла до
	// резерва (keys.backup_dir); Confirm повторяет копию раз в минуту.
	KeyringBackupPending bool `json:"keyring_backup_pending,omitempty"`
	// SignKeyBackupPending — sign.key не подтверждён в keys.backup_dir: копия
	// не прошла или там другой ключ; обслуживание повторяет раз в минуту.
	SignKeyBackupPending bool `json:"sign_key_backup_pending,omitempty"`
	// CopyKeyBackupPending — copy.key не подтверждён в keys.backup_dir: копия
	// наружу не пишется, обслуживание повторяет раз в минуту.
	CopyKeyBackupPending bool `json:"copy_key_backup_pending,omitempty"`
	// OrphanRoots — корни, которых не знает keyring.dat: уничтожение не
	// окончательно, пока оператор их не уничтожит.
	OrphanRoots []string `json:"orphan_roots,omitempty"`
	// RootsUnreachable — каталоги корней не перечисляются (зеркало на
	// упавшей машине): сирот не видно, уничтожение не окончательно.
	RootsUnreachable string `json:"roots_unreachable,omitempty"`
	// Cosigners — свидетели C2SP: последняя подписанная голова, ошибки,
	// отказ (cosign.go).
	Cosigners []CosignerStatus `json:"cosigners,omitempty"`
	// TSAArchive — вторая служба меток (tsa.archive), nil — её нет.
	TSAArchive *ArchiveStatus `json:"tsa_archive,omitempty"`
	// Seal — печать организации на ключ хранилища (seal.file), nil — её нет.
	Seal *SealStatus `json:"seal,omitempty"`
}

func (s *Store) Status() Status {
	var out Status
	s.mu.Lock()
	for name, st := range s.sources {
		out.Sources = append(out.Sources, SourceStatus{
			Name: name, Known: st.known, Disabled: st.cfg.Disabled, Records: st.count,
			MaxSeq: st.maxSeq, LastAt: st.lastAt.UTC(), Silent: st.silent, Epoch: st.epoch,
			LastContact: st.contactAt.UTC(), ContactLost: !st.lostSince.IsZero(),
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
	out.LogKey = cosign.LogVerifierKey(proof.OriginFor(s.signer.PublicKey()), s.signer.PublicKey())
	if err := s.Healthy(); err != nil {
		out.LogFailure = err.Error()
	}
	if err := s.chain.Failed(); err != nil {
		out.ChainFailure = err.Error()
	}
	out.KeyringBackupPending = s.keys.BackupPending()
	out.SignKeyBackupPending = s.signerBackupPending.Load()
	out.CopyKeyBackupPending = s.copyKeyBackupPending.Load()
	if orphans, err := s.keys.OrphanRoots(); err != nil {
		out.RootsUnreachable = err.Error()
	} else {
		out.OrphanRoots = orphans
	}
	out.Cosigners = s.cosignerStatus()
	out.TSAArchive = s.archiveStatus()
	out.Seal = s.sealStatus()
	return out
}

// stretchLocked — листья звеньев после head до звена end включительно: метки
// целиком, остальные хешем (proof.StretchOf) — пакет не показывает чужих
// записей (P-23).
func (s *Store) stretchLocked(head, end uint64) ([]proof.StretchLeaf, error) {
	find := func(seq uint64) (linkRef, bool) {
		i := sort.Search(len(s.links), func(i int) bool { return s.links[i].seq >= seq })
		if i == len(s.links) || s.links[i].seq != seq {
			return linkRef{}, false
		}
		return s.links[i], true
	}
	h, ok1 := find(head)
	e, ok2 := find(end)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("store: links %d and %d are not both in the chain", head, end)
	}
	leaves, err := auditchain.ReadLeafRange(s.chainDir, h.first+h.count, e.first+e.count)
	if err != nil {
		return nil, err
	}
	out := make([]proof.StretchLeaf, len(leaves))
	for i, l := range leaves {
		out[i] = proof.StretchOf(l)
	}
	return out, nil
}
