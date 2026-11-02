package proof

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// Сверка пакета со свидетелем голов (решение 25.10, DECISIONS «Свидетель
// голов»).
//
// Против держателя ключа подписи цепь сама доказывает только время: вторую
// версию цепи он подпишет тем же ключом, метки TSA на ней будут свежие, и
// пакет из неё проверку пройдёт. Свидетель — тот, кто рано получил
// подписанную голову и хранит её вне власти администратора хранилища: канал
// свидетеля (witness.url), газета, копия наружу в чужом хранилище с
// блокировкой. Голова — корень дерева над всеми звеньями до неё, поэтому
// голова у свидетеля закрепляет всю цепь до неё: переписать улику раньше
// этой головы значит разойтись со свидетелем.

// Witness — головы, которые проверяющий сам взял у свидетеля: все, какие
// есть, в том числе прежние версии объектов (поверх запертой версии можно
// положить новую, а запертая остаётся).
type Witness struct {
	Heads []PublishedHead
}

// PublishedHead — подписанная голова (контрольная точка) у свидетеля. Name —
// откуда она взята (имя файла): для отчёта. Refused — голову свидетель
// отверг: сборщик положил её в файл расхождений, потому что она не продолжает
// принятую им. Такая голова — улика второй истории, а не голова свидетеля:
// запись она не закрепляет, а пакет, который с ней сходится, не проходит.
type PublishedHead struct {
	Name       string
	Checkpoint Checkpoint
	Refused    bool
}

// ParseHeads — головы из файла свидетеля name: одна точка (свидетель, копия,
// evidencestore statement) или значения JSON подряд — головы сборщика
// (сборщики-свидетели, п. 31): его последняя (checkpoint.json) и журнал
// (checkpoints.jsonl) — {"received_at", "checkpoint"}, расхождения
// (checkpoints-conflict.jsonl) — {"received_at", "reason", "previous",
// "checkpoint", "consistency"}: «previous» сборщик держал, «checkpoint»
// отверг. Принимаются только эти формы, ключ в ключ: пакет доказательств,
// попавший в каталог, несёт свою подписанную голову, но свидетелем самому себе
// не становится. Значения читаются подряд; с места, которое не разбирается
// (строка, оборванная записью), чтение идёт со следующей строки, так что
// обрывок не прячет следующих голов. Что не разбирается, остаётся пустой
// головой: сверка её не засчитает, а отчёт назовёт, сколько таких.
func ParseHeads(name string, data []byte) []PublishedHead {
	var vals []json.RawMessage
	for rest := bytes.TrimLeft(data, " \t\r\n"); len(rest) > 0; rest = bytes.TrimLeft(rest, " \t\r\n") {
		dec := json.NewDecoder(bytes.NewReader(rest))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err == nil {
			vals = append(vals, raw)
			rest = rest[dec.InputOffset():]
			continue
		}
		vals = append(vals, nil) // не разбирается: пустая голова
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			break
		}
		rest = rest[i+1:]
	}
	if len(vals) == 0 {
		vals = append(vals, nil) // пустой файл — тоже не голова
	}
	var out []PublishedHead
	for i, raw := range vals {
		at := name
		if len(vals) > 1 {
			at = fmt.Sprintf("%s:%d", name, i+1)
		}
		var v map[string]json.RawMessage
		_ = json.Unmarshal(raw, &v)
		parse := func(raw json.RawMessage, refused bool) PublishedHead {
			c, _ := ParseCheckpoint(raw)
			return PublishedHead{Name: at, Checkpoint: c, Refused: refused}
		}
		switch {
		case onlyKeys(v, "origin", "size", "root", "sig"):
			out = append(out, parse(raw, false))
		case onlyKeys(v, "checkpoint", "received_at"):
			out = append(out, parse(v["checkpoint"], false))
		case onlyKeys(v, "previous", "received_at", "reason", "checkpoint", "consistency"):
			out = append(out, parse(v["previous"], false), parse(v["checkpoint"], true))
		default:
			out = append(out, PublishedHead{Name: at})
		}
	}
	return out
}

// onlyKeys — у значения есть первый ключ из keys и нет ключей вне keys.
func onlyKeys(v map[string]json.RawMessage, keys ...string) bool {
	if v[keys[0]] == nil {
		return false
	}
	for k := range v {
		if !slices.Contains(keys, k) {
			return false
		}
	}
	return true
}

// checkWitness сверяет пакет с головами свидетеля. evLink — звено улики,
// links — звенья пакета подряд, rootAt — корень дерева звеньев на звене
// пакета. add — пункт отчёта, как в Verify.
func checkWitness(w *Witness, key ed25519.PublicKey, evLink uint64, links []auditchain.Record, rootAt func(uint64) ([32]byte, bool),
	r *Report, add func(string, error, string) bool) {
	r.WitnessChecked = true

	// Силу имеют только головы, подписанные ключом хранилища: чужие и
	// испорченные файлы ничего не доказывают ни за, ни против. Под одним
	// номером бывает больше одной головы: тогда хранилище подписало две версии
	// цепи, и сохраняются все.
	versions := map[uint64][]PublishedHead{}
	var refused []PublishedHead
	signed := 0
	for _, h := range w.Heads {
		if VerifyCheckpoint(h.Checkpoint, key) != nil {
			continue
		}
		signed++
		if h.Refused {
			refused = append(refused, h)
			continue
		}
		seq, known := h.Checkpoint.Size, false
		for _, v := range versions[seq] {
			known = known || bytes.Equal(v.Checkpoint.Root, h.Checkpoint.Root)
		}
		if !known {
			versions[seq] = append(versions[seq], h)
		}
	}
	seqs := make([]uint64, 0, len(versions))
	for seq := range versions {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	// Каждая голова свидетеля, чьё звено есть в пакете, обязана с ним
	// совпасть — каждая её версия: иначе пакет из другой версии цепи или этот
	// участок цепи существует в двух версиях. Две версии вне участка пакета
	// запись не задевают: её закрепляет голова свидетеля внутри участка, а
	// развилка дальше — замечание в отчёте, а не провал (P-11).
	first, last := links[0].Seq, links[len(links)-1].Seq
	var err error
	for _, seq := range seqs {
		vs := versions[seq]
		if seq < first || seq > last {
			if len(vs) > 1 && r.WitnessFork == 0 {
				r.WitnessFork = seq
			}
			continue
		}
		for _, h := range vs {
			if root, _ := rootAt(seq); h.Checkpoint.RootHash() == root {
				continue
			}
			if len(vs) > 1 {
				err = fmt.Errorf("the witness holds two different heads number %d (%s and %s), both signed with the store key: this part of the chain exists in two versions", seq, vs[0].Name, vs[1].Name)
			} else {
				err = fmt.Errorf("the chain in the bundle up to link %d differs from head %d the witness saw (%s): the chain was rewritten after the witness saw it", seq, seq, h.Name)
			}
			break
		}
		if err != nil {
			break
		}
	}
	// Голова, которую сборщик отверг, запись не закрепляет. Пакет, который с
	// ней сходится, — из той истории, что сборщик отверг, и не проходит, даже
	// если ту же голову принял другой сборщик: тот мог принять её на веру
	// (первая голова) или держать голову старше переписанного места, а честное
	// хранилище головы меньше отданной не отдаёт (P-28). Не сходится или лежит
	// вне пакета — только замечание: хранилище показывало сборщику вторую
	// историю.
	for _, h := range refused {
		root, in := rootAt(h.Checkpoint.Size)
		if err != nil || !in || h.Checkpoint.RootHash() != root {
			continue
		}
		err = fmt.Errorf("the chain in the bundle agrees with head %d that a collector refused (%s): the store showed that collector a second history, or lost the end of its chain", h.Checkpoint.Size, h.Name)
	}
	r.WitnessRefused = len(refused)
	// Улику закрепляет первая голова свидетеля не раньше её звена (и не
	// раньше первого звена пакета); пакет обязан до неё доходить.
	i := sort.Search(len(seqs), func(i int) bool { return seqs[i] >= max(evLink, first) })
	switch {
	case err != nil:
	case i == len(seqs):
		r.WitnessNone = true
	case seqs[i] > last:
		err = fmt.Errorf("the bundle ends at link %d, before head %d the witness saw: request a bundle up to it (evidencestore proof -to-head %d)", last, seqs[i], seqs[i])
	default:
		r.WitnessHead = seqs[i]
	}
	counted := fmt.Sprintf("%d heads signed with the store key, %d of %d entries are not such heads", len(seqs), len(w.Heads)-signed, len(w.Heads))
	detail := "the witness has no head at or after the record's link yet; " + counted
	if r.WitnessHead != 0 {
		detail = fmt.Sprintf("head %d; %s", r.WitnessHead, counted)
	}
	add("the chain in the bundle agrees with the heads the witness saw", err, detail)
}
