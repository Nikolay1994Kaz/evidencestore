package proof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

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
// положить новую, а запертая остаётся). Versions — список версий объектов
// голов у свидетеля S3 (вывод aws s3api list-object-versions в том же
// каталоге): когда свидетель получил каждую (P-21).
type Witness struct {
	Heads    []PublishedHead
	Versions []HeadVersion
}

// PublishedHead — подписанная голова (контрольная точка) у свидетеля. Name —
// откуда она взята (имя файла): для отчёта. Refused — голову свидетель
// отверг: сборщик положил её в файл расхождений, потому что она не продолжает
// принятую им. Такая голова — улика второй истории, а не голова свидетеля:
// запись она не закрепляет, а пакет, который с ней сходится, не проходит.
// Received — когда свидетель получил голову: received_at сборщика; у головы
// из S3 — время её версии из списка версий (AddFile). Ноль — неизвестно.
type PublishedHead struct {
	Name       string
	Checkpoint Checkpoint
	Refused    bool
	Received   time.Time
	// digest — MD5 файла, где голова лежит одна: так голова из S3 находит
	// свою версию в списке (ETag одной записи PUT).
	digest string
}

// HeadVersion — версия объекта головы у свидетеля S3: ключ, номер головы из
// имени ключа («…heads/<номер>.json»), номер версии, ETag и время, когда S3
// принял версию (LastModified: его ставит S3, а не тот, кто пишет).
type HeadVersion struct {
	Key       string
	Size      uint64
	VersionID string
	ETag      string
	At        time.Time
}

// AddFile — файл из каталога голов: список версий S3 или головы (ParseHeads).
// Голова, которая лежит в файле одна (объект S3, скачанный по версии),
// запоминает MD5 файла: по нему или по номеру версии в имени файла она
// найдёт свою версию в списке.
func (w *Witness) AddFile(name string, data []byte) {
	if vs, ok := parseHeadVersions(data); ok {
		w.Versions = append(w.Versions, vs...)
		return
	}
	hs := ParseHeads(name, data)
	if len(hs) == 1 {
		sum := md5.Sum(data)
		hs[0].digest = hex.EncodeToString(sum[:])
	}
	w.Heads = append(w.Heads, hs...)
}

// parseHeadVersions — вывод aws s3api list-object-versions: объект с массивом
// Versions. Берутся версии ключей «…heads/<номер>.json»; LastModified — в
// записи CLI v1 («…000Z») или v2 («…+00:00»).
func parseHeadVersions(data []byte) ([]HeadVersion, bool) {
	var probe map[string]json.RawMessage
	if json.Unmarshal(data, &probe) != nil || probe["Versions"] == nil {
		return nil, false
	}
	var list struct {
		Versions []struct {
			Key          string `json:"Key"`
			VersionID    string `json:"VersionId"`
			ETag         string `json:"ETag"`
			LastModified string `json:"LastModified"`
		} `json:"Versions"`
	}
	if json.Unmarshal(data, &list) != nil {
		return nil, false
	}
	var out []HeadVersion
	for _, v := range list.Versions {
		size, ok := headKey(v.Key)
		at, err := time.Parse(time.RFC3339Nano, v.LastModified)
		if !ok || err != nil {
			continue
		}
		out = append(out, HeadVersion{Key: v.Key, Size: size, VersionID: v.VersionID, ETag: strings.Trim(v.ETag, `"`), At: at})
	}
	return out, true
}

// headKey — номер головы из ключа «…heads/<номер>.json»: так её кладёт
// хранилище (heads/%020d.json).
func headKey(key string) (uint64, bool) {
	i := strings.LastIndex(key, "heads/")
	if i < 0 || i > 0 && key[i-1] != '/' {
		return 0, false
	}
	num, ok := strings.CutSuffix(key[i+len("heads/"):], ".json")
	if !ok || num == "" || strings.Trim(num, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseUint(num, 10, 64)
	return n, err == nil
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
		// received_at сборщика — по его часам; голова расхождения «previous»
		// получена не позже строки.
		var received time.Time
		_ = json.Unmarshal(v["received_at"], &received)
		parse := func(raw json.RawMessage, refused bool) PublishedHead {
			c, _ := ParseCheckpoint(raw)
			return PublishedHead{Name: at, Checkpoint: c, Refused: refused, Received: received}
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

	// Время получения головы из S3 — по версии её файла в списке версий: ETag
	// — MD5 файла или номер версии — в имени файла; из нескольких версий —
	// самая ранняя (P-21). Версия, нашедшая файл, — не неизвестная, даже если
	// файл не голова: мусор, положенный поверх головы, сверку не ломает (P-93).
	matched := make([]bool, len(w.Versions))
	received := func(h PublishedHead) time.Time {
		at := h.Received
		if h.digest == "" {
			return at
		}
		for i, v := range w.Versions {
			if v.ETag != h.digest && (v.VersionID == "" || !strings.Contains(h.Name, v.VersionID)) {
				continue
			}
			matched[i] = true
			if at.IsZero() || v.At.Before(at) {
				at = v.At
			}
		}
		return at
	}

	// Силу имеют только головы, подписанные ключом хранилища: чужие и
	// испорченные файлы ничего не доказывают ни за, ни против. Под одним
	// номером бывает больше одной головы: тогда хранилище подписало две версии
	// цепи, и сохраняются все. Одна голова в нескольких файлах — одна, с самым
	// ранним временем получения.
	versions := map[uint64][]PublishedHead{}
	var refused []PublishedHead
	signed := 0
	for _, h := range w.Heads {
		h.Received = received(h)
		if VerifyCheckpoint(h.Checkpoint, key) != nil {
			continue
		}
		signed++
		if h.Refused {
			refused = append(refused, h)
			continue
		}
		seq, known := h.Checkpoint.Size, false
		for i, v := range versions[seq] {
			if !bytes.Equal(v.Checkpoint.Root, h.Checkpoint.Root) {
				continue
			}
			known = true
			if !h.Received.IsZero() && (v.Received.IsZero() || h.Received.Before(v.Received)) {
				versions[seq][i].Received = h.Received
			}
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

	// Улику закрепляет голова свидетеля не раньше её звена (и не раньше
	// первого звена пакета), которую свидетель получил первой: переписать
	// цепь после этого — разойтись с ней. Не первая по номеру: держатель
	// sign.key и ключей свидетеля кладёт позже голову под свободным номером
	// между звеном и ней, и такая голова пришла к свидетелю позже (P-21).
	// При равном времени — бо́льший номер: пакет до него длиннее, и только.
	// Пакет обязан дойти до закрепляющей.
	lo := max(evLink, first)
	var fix uint64
	var fixAt time.Time
	for _, seq := range seqs {
		for _, h := range versions[seq] {
			if seq < lo || h.Received.IsZero() {
				continue
			}
			if fixAt.IsZero() || h.Received.Before(fixAt) || h.Received.Equal(fixAt) && seq > fix {
				fix, fixAt = seq, h.Received
			}
		}
	}
	// Версия из списка без файла: её голова неизвестна. Лежит она на участке
	// пакета или получена не позже закрепляющей — сверке её не хватает, и её
	// надо скачать.
	for i, v := range w.Versions {
		if matched[i] || err != nil {
			continue
		}
		if first <= v.Size && v.Size <= last || v.Size >= lo && (fixAt.IsZero() || !v.At.After(fixAt)) {
			err = fmt.Errorf("the S3 versions list names %s version %q, received at %s, and no file in the heads directory is that version (its MD5 is the ETag of a single-part upload, or its name holds the version ID): download every version of the heads, each to a file named after its version ID (aws s3api get-object --version-id)", v.Key, v.VersionID, fmtTime(v.At))
		}
	}
	i := sort.Search(len(seqs), func(i int) bool { return seqs[i] >= lo })
	switch {
	case err != nil:
	case fixAt.IsZero() && i == len(seqs):
		r.WitnessNone = true
	case fixAt.IsZero():
		// Ни у одной головы не раньше звена нет времени получения: первая по
		// номеру, с замечанием (P-21).
		fix, r.WitnessUntimed = seqs[i], true
	}
	switch {
	case err != nil || r.WitnessNone:
	case fix > last:
		err = fmt.Errorf("the bundle ends at link %d, before head %d the witness %s: request a bundle up to it (evidencestore proof -to-head %d)", last, fix, receivedFirst(fixAt), fix)
	default:
		r.WitnessHead, r.WitnessReceived = fix, fixAt
	}
	counted := fmt.Sprintf("%d heads signed with the store key, %d of %d entries are not such heads", len(seqs), len(w.Heads)-signed, len(w.Heads))
	if len(w.Versions) > 0 {
		counted += fmt.Sprintf(", %d versions in the S3 versions list", len(w.Versions))
	}
	detail := "the witness has no head at or after the record's link yet; " + counted
	if r.WitnessHead != 0 {
		detail = fmt.Sprintf("head %d, which the witness %s; %s", r.WitnessHead, receivedFirst(fixAt), counted)
	}
	add("the chain in the bundle agrees with the heads the witness saw", err, detail)
}

// receivedFirst — как голова стала закрепляющей: первой полученной (со
// временем) или первой по номеру (времени у голов нет: об этом — заметка).
func receivedFirst(at time.Time) string {
	if at.IsZero() {
		return "saw"
	}
	return "received first, at " + fmtTime(at)
}

// WitnessUntimedNote — голов свидетеля со временем получения нет, и запись
// закрепила первая по номеру: голову под свободным номером, положенную
// позже, сверка не отличит (P-21).
const WitnessUntimedNote = "the witness's heads at or after this point carry no time of receipt, so the first by number fixes it: a head added to the witness later under an unused number would be taken instead (P-21). Put the S3 versions list next to the heads (aws s3api list-object-versions … > DIR/versions.json, every version of the heads downloaded), or use a collector's head journal, which carries received_at; otherwise check the receipt times yourself (docs/copy-and-witness.md)"
