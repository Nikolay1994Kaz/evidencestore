package proof

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
)

// Улика из журнала гейтвея несёт второй лист — вердикт хранилища при приёме
// (gateway.Verdict): открытые поля цепочки гейтвея (seq, hash, prev_hash) и
// что сошлось. Лист ложится в цепь рядом с уликой и, как и она, остаётся
// проверяемым после уничтожения ключа месяца.
//
// Пакет по такой улике доказывает больше обычного: тело — именно та запись
// журнала гейтвея (хэш пересчитывается из тела), и её накрывает контрольная
// точка, подписанная ключом гейтвея (проверяющий проверяет подпись своим
// ключом). Сцепку записи с контрольной точкой — хэши промежуточных записей —
// проверило хранилище при приёме: промежуточных записей в пакете нет.

type gatewayPayload struct {
	Pos     uint64          `json:"pos"`
	Verdict gateway.Verdict `json:"verdict"`
}

// GatewayLeaf — лист вердикта по записи журнала гейтвея.
func GatewayLeaf(h evidence.Header, pos uint64, v gateway.Verdict) auditchain.Leaf {
	payload, _ := json.Marshal(gatewayPayload{Pos: pos, Verdict: v}) // типы без каналов и функций: ошибки нет
	return auditchain.Leaf{
		UnixNano: h.ReceivedAt,
		Type:     auditchain.EventGateway,
		Scope:    h.Source,
		Subject:  strconv.FormatUint(h.Seq, 10),
		Payload:  payload,
	}
}

// ParseGatewayLeaf разбирает лист вердикта: позиция улики и вердикт.
func ParseGatewayLeaf(l auditchain.Leaf) (uint64, gateway.Verdict, error) {
	if l.Type != auditchain.EventGateway {
		return 0, gateway.Verdict{}, errors.New("proof: not a gateway verdict leaf")
	}
	var p gatewayPayload
	if err := json.Unmarshal(l.Payload, &p); err != nil {
		return 0, gateway.Verdict{}, fmt.Errorf("proof: gateway verdict leaf: %w", err)
	}
	return p.Pos, p.Verdict, nil
}

// GatewayProof — часть пакета для улики из журнала гейтвея: лист вердикта по
// ней и, если есть, лист контрольной точки гейтвея после неё в той же
// цепочке без разрывов между ними.
type GatewayProof struct {
	Entry      Inclusion  `json:"entry"`
	Checkpoint *Inclusion `json:"checkpoint,omitempty"`
}

// verifyGateway — проверки улики гейтвея. add — пункт отчёта, как в Verify.
func verifyGateway(g *GatewayProof, sealed evidence.Sealed, r *Report, trust Trust,
	linkAt func(uint64) (auditchain.Record, [32]byte, bool), add func(string, error, string) bool) {

	leaf := g.Entry.Leaf.chain()
	pos, v, err := ParseGatewayLeaf(leaf)
	if err == nil {
		switch {
		case leaf.Scope != sealed.Source || leaf.Subject != strconv.FormatUint(sealed.Seq, 10):
			err = fmt.Errorf("the verdict is about %s/%s, the record is %s/%d", leaf.Scope, leaf.Subject, sealed.Source, sealed.Seq)
		case pos != r.Position:
			err = fmt.Errorf("the verdict is about position %d, the record is at position %d", pos, r.Position)
		}
	}
	if !add("the gateway verdict describes this record", err, "") {
		return
	}
	r.Gateway = &v
	add("the gateway verdict is in the chain (Merkle path)", checkInclusion(g.Entry, linkAt), fmt.Sprintf("link %d", g.Entry.LinkSeq))

	err = nil
	if !v.Clean() {
		err = fmt.Errorf("chaining %s, hash matches: %v, signature: %s; %s", v.Link, v.HashOK, orDash(v.Signature), v.Problem)
	}
	add("the entry is intact in the gateway chain (checked by the store at intake)", err, fmt.Sprintf("seq %d, chaining %s", v.Seq, v.Link))

	if r.BodyOpened {
		e, err := gateway.ParseEntry(r.Body)
		var h string
		if err == nil {
			h, err = e.ComputeHash()
		}
		if err == nil && (h != v.Hash || e.Hash != v.Hash) {
			err = fmt.Errorf("body hash %s, verdict hash %s", short(h), short(v.Hash))
		}
		add("the body is that very gateway journal entry (hash recomputed)", err, short(v.Hash))
	}

	if g.Checkpoint == nil {
		return
	}
	cl := g.Checkpoint.Leaf.chain()
	cpos, cv, err := ParseGatewayLeaf(cl)
	if err == nil {
		switch {
		case cl.Scope != sealed.Source:
			err = fmt.Errorf("the checkpoint belongs to another source, %s", cl.Scope)
		case cv.Type != "checkpoint" || cv.Sig == "":
			err = errors.New("the leaf is not a signed checkpoint")
		case cv.Namespace() != v.Namespace():
			err = errors.New("the checkpoint belongs to another gateway chain")
		case cpos <= pos || cv.Seq <= v.Seq:
			err = errors.New("the checkpoint does not come after the entry")
		}
	}
	if err == nil {
		err = checkInclusion(*g.Checkpoint, linkAt)
	}
	if !add("a gateway checkpoint after the entry is in the chain", err, fmt.Sprintf("seq %d", cv.Seq)) {
		return
	}
	// Накрывает запись только точка, чью подпись кто-то проверил: сам
	// проверяющий своим ключом или хранилище при приёме закреплённым ключом
	// гейтвея. Подпись без проверки — просто байты.
	switch {
	case trust.GatewayKey != nil:
		r.GatewayKeyChecked = true
		if add("the checkpoint is signed with the pinned gateway key", gateway.VerifyCheckpoint(trust.GatewayKey, cv), fmt.Sprintf("seq %d", cv.Seq)) {
			r.GatewayCheckpoint = &cv
		}
	case cv.Signature == gateway.SigValid:
		r.GatewayCheckpoint = &cv
	default:
		r.GatewayUnsigned = true
	}
}

// gatewayNotes — пределы доказательства по улике гейтвея.
func (r Report) gatewayNotes() []string {
	if r.Gateway == nil {
		return nil
	}
	var n []string
	if r.Gateway.Link == gateway.LinkFirstSeen {
		n = append(n, "the gateway chain began before the first entry received: the store never saw the entries before it")
	}
	switch {
	case r.GatewayUnsigned:
		n = append(n, "there is a checkpoint after the entry, but nobody checked its signature: the gateway key is pinned neither in the store's registry nor by you (esverify -gateway-key), so no gateway signature covers this entry")
	case r.GatewayCheckpoint == nil:
		n = append(n, "the bundle has no gateway checkpoint after the entry: no gateway signature covers it (the checkpoint has not arrived yet, or the chain breaks before it)")
	case !r.GatewayKeyChecked:
		n = append(n, "the store checked the checkpoint signature at intake; pin the gateway key (esverify -gateway-key) to check it yourself")
	}
	if r.GatewayCheckpoint != nil {
		n = append(n, "the store checked at intake that the entry chains to the checkpoint (the hashes of the entries in between); those entries are not in the bundle")
	}
	return n
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
