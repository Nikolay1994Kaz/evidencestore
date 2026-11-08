package proof

import (
	"cmp"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
)

// Подпись свидетеля C2SP в пакете (DECISIONS п. 34).
//
// Свидетель C2SP (witness.cosigners, internal/witness) подписывает голову,
// только сверив доказательство продолжения от последней, которую подписал
// сам: все головы, подписанные одним свидетелем, — одна история. Подпись
// несёт время свидетеля. Пакет везёт подпись готовой, и проверяющий сверяет
// её офлайн открытым ключом свидетеля (esverify -witness-key), без доступа
// к свидетелю.
//
// Что доказывает подпись головы N ≥ звена улики, сошедшаяся с корнем дерева
// звеньев пакета на N: в момент T свидетель видел цепь, в которой звено улики
// такое, как в пакете. Переписать запись позже значит разойтись со всеми
// головами, которые свидетель подписал с тех пор: следующую он не подпишет.
// Не доказывает: что цепь не переписали раньше, чем свидетель получил первую
// голову после звена улики (witness.every, минута по умолчанию), и честность
// самого свидетеля и его часов.

// Cosignature — подпись свидетеля над головой цепи: имя свидетеля, размер и
// корень головы и подпись в виде строки заметки C2SP (номер ключа ‖ время ‖
// подпись Ed25519, cosignature/v1). Происхождение в пакет не кладётся: оно
// выводится из закреплённого ключа хранилища (OriginFor).
type Cosignature struct {
	Name string `json:"name"`
	Size uint64 `json:"size"`
	Root []byte `json:"root"`
	Sig  []byte `json:"sig"`
}

// Time — время подписи по часам свидетеля, без проверки подписи: для показа
// и выбора. Ноль — подпись не разбирается.
func (c Cosignature) Time() time.Time {
	if len(c.Sig) != cosign.BlobSize {
		return time.Time{}
	}
	var ts uint64
	for _, b := range c.Sig[4:12] {
		ts = ts<<8 | uint64(b)
	}
	return time.Unix(int64(ts), 0).UTC()
}

// CosignedHead — что закрепил один свидетель: голова, которую он подписал
// раньше всех не раньше звена улики, и время подписи.
type CosignedHead struct {
	Witness string    `json:"witness"`
	Size    uint64    `json:"size"`
	Time    time.Time `json:"time"`
}

func (c CosignedHead) String() string {
	return fmt.Sprintf("%s: head %d, cosigned at %s", c.Witness, c.Size, fmtTime(c.Time))
}

// Note — точка в виде подписанной заметки C2SP: текст, пустая строка и
// подпись хранилища (тип 0x01, имя ключа — происхождение). В таком виде её
// принимает свидетель (add-checkpoint).
func (c Checkpoint) Note(pub ed25519.PublicKey) []byte {
	return append(append(c.body(), '\n'), cosign.LogSignature(c.Origin, pub, c.Signature)...)
}

// CosignNotes — заметки отчёта о подписях свидетелей; part — что они
// закрепляют («this record», «this stretch», «this part»).
func CosignNotes(checked bool, pins []CosignedHead, unknown, carried int, part string) []string {
	var n []string
	for _, p := range pins {
		n = append(n, fmt.Sprintf("witness %s cosigned head %d at %s, after checking that it extends every head it had cosigned before: a rewrite of %s after that time would contradict its cosignature, as long as the witness and its key are out of the store administrator's reach; a rewrite made before it received a head after %s is not caught", p.Witness, p.Size, fmtTime(p.Time), part, part))
	}
	switch {
	case !checked && carried > 0:
		n = append(n, fmt.Sprintf("the bundle carries %d witness cosignatures, not checked: pass each witness's key with -witness-key, taken from the witness's operator, not from the store", carried))
	case checked && unknown > 0:
		n = append(n, fmt.Sprintf("%d cosignatures in the bundle are by witnesses whose keys were not given with -witness-key: they were not checked", unknown))
	}
	return n
}

// cosignCheckName — пункт отчёта о подписях свидетелей.
const cosignCheckName = "every witness given with -witness-key cosigned a head at or after this point, and the chain in the bundle agrees with it"

// cosignDetail — подробность пункта: кто что закрепил.
func cosignDetail(pins []CosignedHead) string {
	each := make([]string, 0, len(pins))
	for _, p := range pins {
		each = append(each, p.String())
	}
	return strings.Join(each, "; ")
}

// checkCosigned сверяет подписи свидетелей в пакете. evLink — звено, которое
// закрепляется (звено улики; у пакетов за окно и по источнику — конец
// участка), links — звенья пакета подряд, rootAt — корень дерева звеньев на
// звене пакета.
//
// Каждый закреплённый свидетель обязан подписать голову не раньше evLink и
// не раньше первого звена пакета. Из таких берётся подписанная раньше всех
// (на равном времени — меньшая): с неё запись закреплена. Подпись головы
// внутри пакета обязана сойтись с корнем дерева пакета на её размере — иначе
// свидетель видел другую историю. Подпись под именем и номером закреплённого
// ключа, которая не сходится, — провал (signed-note: такая заметка
// испорчена); подписи чужих ключей не в счёт (unknown).
func checkCosigned(cs []Cosignature, keys []cosign.Verifier, storeKey ed25519.PublicKey, evLink uint64,
	links []auditchain.Record, rootAt func(uint64) ([32]byte, bool)) (pins []CosignedHead, unknown int, err error) {
	if len(storeKey) != ed25519.PublicKeySize {
		return nil, 0, errors.New("no pinned store key to name the chain the witnesses cosigned")
	}
	origin := OriginFor(storeKey)
	first, last := links[0].Seq, links[len(links)-1].Seq
	lo := max(evLink, first)

	// Ключи по имени и номеру, без повторов: отчёт не зависит от порядка флагов.
	keys = slices.Clone(keys)
	slices.SortFunc(keys, func(a, b cosign.Verifier) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	keys = slices.CompactFunc(keys, func(a, b cosign.Verifier) bool { return a.Name == b.Name && a.ID == b.ID })

	type pick struct{ size, at uint64 }
	inside := make([]*pick, len(keys)) // подписанная раньше всех голова внутри пакета
	beyond := make([]*pick, len(keys)) // она же дальше конца пакета
	better := func(p *pick, size, at uint64) bool {
		return p == nil || at < p.at || at == p.at && size < p.size
	}
	for _, c := range cs {
		known := false
		for i, k := range keys {
			// Подпись этого ключа — по имени и номеру; чужую пропускаем.
			if c.Name != k.Name || len(c.Sig) < 4 || binary.BigEndian.Uint32(c.Sig) != k.ID {
				continue
			}
			known = true
			if len(c.Root) != 32 || c.Size == 0 {
				return nil, 0, fmt.Errorf("the cosignature of witness %s names head %d with a root of %d bytes: it does not parse", c.Name, c.Size, len(c.Root))
			}
			at, err := k.Verify(cosign.CheckpointText(origin, c.Size, [32]byte(c.Root)), c.Sig)
			if err != nil {
				return nil, 0, fmt.Errorf("the cosignature of witness %s on head %d: %w", c.Name, c.Size, err)
			}
			if first <= c.Size && c.Size <= last {
				if root, ok := rootAt(c.Size); !ok || root != [32]byte(c.Root) {
					return nil, 0, fmt.Errorf("witness %s cosigned head %d at %s with a root that differs from the chain in the bundle: the chain was rewritten after the witness saw it, or the bundle comes from another history", c.Name, c.Size, fmtTime(time.Unix(int64(at), 0)))
				}
			}
			switch {
			case c.Size < lo:
				// Подпись раньше закрепляемого звена ничего не закрепляет.
			case c.Size <= last:
				if better(inside[i], c.Size, at) {
					inside[i] = &pick{c.Size, at}
				}
			default:
				if better(beyond[i], c.Size, at) {
					beyond[i] = &pick{c.Size, at}
				}
			}
		}
		if !known {
			unknown++
		}
	}
	for i, k := range keys {
		switch p := inside[i]; {
		case p != nil:
			pins = append(pins, CosignedHead{Witness: k.Name, Size: p.size, Time: time.Unix(int64(p.at), 0).UTC()})
		case beyond[i] != nil:
			b := beyond[i]
			return nil, unknown, fmt.Errorf("the bundle ends at link %d, before head %d that witness %s cosigned at %s: request a bundle up to it (evidencestore proof … -to-head %d)", last, b.size, k.Name, fmtTime(time.Unix(int64(b.at), 0)), b.size)
		default:
			return nil, unknown, fmt.Errorf("the bundle carries no cosignature of witness %s on a head at or after link %d: the store has not had a head cosigned by it since then, or the cosignature was taken out of the bundle; ask for the bundle again later", k.Name, lo)
		}
	}
	return pins, unknown, nil
}
