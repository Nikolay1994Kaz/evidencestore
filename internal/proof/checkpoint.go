package proof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// Контрольная точка — подписанная голова цепи (DECISIONS п. 30): число
// звеньев N и корень дерева RFC 6962 над их хешами (tree.go). Что одна точка
// продолжает другую, доказывается за log₂N хешей, и такую голову понимают
// свидетели C2SP. Голова прежнего вида — номер и хеш последнего звена
// (auditchain.Statement) — наружу больше не уходит.
//
// Подписывается тело контрольной точки C2SP (tlog-checkpoint):
//
//	evidencestore/<16 hex>
//	<N>
//	<корень, base64>
//
// Та же подпись годится как подпись заметки C2SP (signed note) с именем
// ключа, равным происхождению. Времени в теле нет: время головы доказывает
// метка TSA, время получения — сам свидетель, а слово хранилища о времени
// ничего не доказывает; две точки одного размера одной цепи совпадают байт в
// байт. Остальные подписи хранилища начинаются с длины своего домена
// (4 байта, первый — 0), тело точки — с буквы: подпись одного вида не выдать
// за подпись другого.

// Checkpoint — подписанная контрольная точка.
type Checkpoint struct {
	Origin    string `json:"origin"`
	Size      uint64 `json:"size"` // звеньев в цепи: номер последнего
	Root      []byte `json:"root"` // корень дерева звеньев, 32 байта
	Signature []byte `json:"sig"`
}

const originPrefix = "evidencestore/"

// OriginFor — происхождение цепи хранилища с ключом pub: по нему точку
// одного хранилища не спутать с точкой другого.
func OriginFor(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return originPrefix + hex.EncodeToString(sum[:8])
}

// body — подписываемое тело.
func (c Checkpoint) body() []byte {
	return fmt.Appendf(nil, "%s\n%d\n%s\n", c.Origin, c.Size, base64.StdEncoding.EncodeToString(c.Root))
}

// SignCheckpoint — точка размера size с корнем root, подписанная ключом
// хранилища.
func SignCheckpoint(s *auditchain.Signer, size uint64, root [32]byte) Checkpoint {
	c := Checkpoint{Origin: OriginFor(s.PublicKey()), Size: size, Root: root[:]}
	c.Signature = s.SignMessage(c.body())
	return c
}

// VerifyCheckpoint проверяет точку закреплённым ключом хранилища.
func VerifyCheckpoint(c Checkpoint, key ed25519.PublicKey) error {
	switch {
	case len(key) != ed25519.PublicKeySize:
		return errors.New("no pinned store key to check the checkpoint with")
	case c.Origin != OriginFor(key):
		return fmt.Errorf("the checkpoint is of log %q, the pinned key's log is %q", c.Origin, OriginFor(key))
	case c.Size == 0:
		return errors.New("the checkpoint is of an empty chain")
	case len(c.Root) != 32:
		return errors.New("the checkpoint's root is not 32 bytes")
	case !ed25519.Verify(key, c.body(), c.Signature):
		return errors.New("the checkpoint's signature does not match the pinned store key")
	}
	return nil
}

// RootHash — корень точки массивом.
func (c Checkpoint) RootHash() (root [32]byte) {
	copy(root[:], c.Root)
	return root
}

// JSON — точка текстом: так она уходит свидетелю, в копию и оператору.
func (c Checkpoint) JSON() ([]byte, error) { return json.MarshalIndent(c, "", "  ") }

// CheckExtends — consistency доказывает (tlog.ProveTree), что голова newer
// продолжает голову older: дерево звеньев newer начинается деревом older.
// Подписи точек не проверяет.
func CheckExtends(newer, older Checkpoint, consistency [][]byte) error {
	p := make(tlog.TreeProof, len(consistency))
	for i, h := range consistency {
		if len(h) != 32 {
			return fmt.Errorf("hash %d of the consistency proof is not 32 bytes", i)
		}
		copy(p[i][:], h)
	}
	if newer.Size > 1<<62 || len(newer.Root) != 32 || len(older.Root) != 32 {
		return errors.New("the heads do not parse")
	}
	if err := tlog.CheckTree(p, int64(newer.Size), tlog.Hash(newer.RootHash()), int64(older.Size), tlog.Hash(older.RootHash())); err != nil {
		return fmt.Errorf("head %d does not extend head %d: %w", newer.Size, older.Size, err)
	}
	return nil
}

// ParseCheckpoint разбирает точку. Подпись не проверяет: это дело
// VerifyCheckpoint.
func ParseCheckpoint(data []byte) (Checkpoint, error) {
	var c Checkpoint
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("proof: checkpoint: %w", err)
	}
	return c, nil
}
