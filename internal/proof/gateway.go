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
			err = fmt.Errorf("вердикт про %s/%s, а улика %s/%d", leaf.Scope, leaf.Subject, sealed.Source, sealed.Seq)
		case pos != r.Position:
			err = fmt.Errorf("вердикт про позицию %d, а улика на позиции %d", pos, r.Position)
		}
	}
	if !add("вердикт гейтвея описывает эту улику", err, "") {
		return
	}
	r.Gateway = &v
	add("вердикт гейтвея входит в цепь (путь Меркла)", checkInclusion(g.Entry, linkAt), fmt.Sprintf("звено %d", g.Entry.LinkSeq))

	err = nil
	if !v.Clean() {
		err = fmt.Errorf("сцепка %s, хэш сошёлся: %v, подпись: %s; %s", v.Link, v.HashOK, orDash(v.Signature), v.Problem)
	}
	add("запись цела в цепочке гейтвея (проверено хранилищем при приёме)", err, fmt.Sprintf("seq %d, сцепка %s", v.Seq, v.Link))

	if r.BodyOpened {
		e, err := gateway.ParseEntry(r.Body)
		var h string
		if err == nil {
			h, err = e.ComputeHash()
		}
		if err == nil && (h != v.Hash || e.Hash != v.Hash) {
			err = fmt.Errorf("хэш тела %s, в вердикте %s", short(h), short(v.Hash))
		}
		add("тело — та самая запись журнала гейтвея (хэш пересчитан)", err, short(v.Hash))
	}

	if g.Checkpoint == nil {
		return
	}
	cl := g.Checkpoint.Leaf.chain()
	cpos, cv, err := ParseGatewayLeaf(cl)
	if err == nil {
		switch {
		case cl.Scope != sealed.Source:
			err = fmt.Errorf("контрольная точка другого источника %s", cl.Scope)
		case cv.Type != "checkpoint" || cv.Sig == "":
			err = errors.New("лист не контрольная точка с подписью")
		case cv.Namespace() != v.Namespace():
			err = errors.New("контрольная точка другой цепочки гейтвея")
		case cpos <= pos || cv.Seq <= v.Seq:
			err = errors.New("контрольная точка не после записи")
		}
	}
	if err == nil {
		err = checkInclusion(*g.Checkpoint, linkAt)
	}
	if !add("контрольная точка гейтвея после записи входит в цепь", err, fmt.Sprintf("seq %d", cv.Seq)) {
		return
	}
	// Накрывает запись только точка, чью подпись кто-то проверил: сам
	// проверяющий своим ключом или хранилище при приёме закреплённым ключом
	// гейтвея. Подпись без проверки — просто байты.
	switch {
	case trust.GatewayKey != nil:
		r.GatewayKeyChecked = true
		if add("контрольная точка подписана закреплённым ключом гейтвея", gateway.VerifyCheckpoint(trust.GatewayKey, cv), fmt.Sprintf("seq %d", cv.Seq)) {
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
		n = append(n, "цепочка гейтвея началась раньше первой полученной записи: предыдущих записей хранилище не видело")
	}
	switch {
	case r.GatewayUnsigned:
		n = append(n, "контрольная точка после записи есть, но её подпись не проверял никто: ключ гейтвея не закреплён ни в реестре хранилища, ни у вас (esverify -gateway-key) — подпись гейтвея эту запись не накрывает")
	case r.GatewayCheckpoint == nil:
		n = append(n, "контрольной точки гейтвея после записи в пакете нет: подпись гейтвея эту запись не накрывает (точка ещё не пришла или в цепочке до неё есть поломка)")
	case !r.GatewayKeyChecked:
		n = append(n, "подпись контрольной точки проверило хранилище при приёме; закрепите ключ гейтвея (esverify -gateway-key), чтобы проверить её самим")
	}
	if r.GatewayCheckpoint != nil {
		n = append(n, "сцепку записи с контрольной точкой (хэши промежуточных записей) проверило хранилище при приёме: промежуточных записей в пакете нет")
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
