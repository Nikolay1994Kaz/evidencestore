package proof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
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
	// pages — файлы списка версий, которые лишь страница списка (у них есть
	// NextToken или IsTruncated): сверка с ними отказывает (P-105).
	pages []string
}

// PublishedHead — подписанная голова (контрольная точка) у свидетеля. Name —
// откуда она взята (имя файла): для отчёта. Refused — голову свидетель
// отверг: сборщик положил её в файл расхождений, потому что она не продолжает
// принятую им. Такая голова — улика второй истории, а не голова свидетеля:
// запись она не закрепляет, а пакет, который с ней сходится, не проходит.
// Received — когда свидетель получил голову: received_at сборщика. У головы
// из файла, который нашёл свою версию в списке версий S3, в счёт идёт только
// время версии: содержимое объекта пишет тот, у кого ключи записи (P-96).
// Ноль — неизвестно.
type PublishedHead struct {
	Name       string
	Checkpoint Checkpoint
	Refused    bool
	Received   time.Time
	// file — файл, откуда голова (у строк журнала Name — «файл:строка»);
	// digest — его MD5: по нему (ETag одной записи PUT) или по имени файла
	// голова из S3 находит свою версию в списке.
	file, digest string
}

// HeadVersion — версия объекта головы у свидетеля S3: ключ, номер головы из
// имени ключа («…heads/<номер>.json»), номер версии, ETag и время, когда S3
// принял версию (LastModified: его ставит S3, а не тот, кто пишет). list —
// файл списка версий, откуда она: один список — один свидетель, где бы ни
// лежали файлы его версий (P-99).
type HeadVersion struct {
	Key       string
	Size      uint64
	VersionID string
	ETag      string
	At        time.Time
	list      string
}

// AddFile — файл из каталога голов: список версий S3 или головы (ParseHeads).
// Каждая голова файла запоминает его MD5: по нему или по имени файла объект
// S3, скачанный по версии, найдёт свою версию в списке — и тогда, когда в нём
// не одна голова или мусор (P-96).
func (w *Witness) AddFile(name string, data []byte) {
	if vs, ok := parseHeadVersions(data); ok {
		for i := range vs {
			vs[i].list = name
		}
		w.Versions = append(w.Versions, vs...)
		if listPage(data) {
			w.pages = append(w.pages, name)
		}
		return
	}
	sum := md5.Sum(data)
	hs := ParseHeads(name, data)
	for i := range hs {
		hs[i].file, hs[i].digest = name, hex.EncodeToString(sum[:])
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
	// Версии ищутся по ETag и по номеру версии — имени файла без «.json»,
	// точно: подстрока совпала бы и с чужим номером (у всех версий, записанных
	// до включения версий, он «null»), а перебор списка на каждый файл — год
	// голов раз в минуту, полмиллиона версий, — шёл бы часами (P-95).
	matched := make([]bool, len(w.Versions))
	byETag, byID := map[string][]int{}, map[string][]int{}
	for i, v := range w.Versions {
		byETag[v.ETag] = append(byETag[v.ETag], i)
		if v.VersionID != "" && v.VersionID != "null" {
			byID[v.VersionID] = append(byID[v.VersionID], i)
		}
	}
	fromS3 := func(h PublishedHead) (at map[string]time.Time, named bool) {
		if h.digest == "" {
			return nil, false
		}
		name := strings.TrimSuffix(filepath.ToSlash(h.file), ".json")
		ids := slices.Concat(byID[name], byID[path.Base(name)])
		for _, i := range slices.Concat(byETag[h.digest], ids) {
			v := w.Versions[i]
			matched[i] = true
			if at == nil {
				at = map[string]time.Time{}
			}
			if t, ok := at[v.list]; !ok || v.At.Before(t) {
				at[v.list] = v.At
			}
		}
		return at, len(ids) > 0
	}

	// Силу имеют только головы, подписанные ключом хранилища: чужие и
	// испорченные файлы ничего не доказывают ни за, ни против. Под одним
	// номером бывает больше одной головы: тогда хранилище подписало две версии
	// цепи, и сохраняются все. Каждую голову видел свой свидетель (sightingOf):
	// по ним — закрепление ниже.
	versions := map[uint64][]PublishedHead{}
	var refused []PublishedHead
	var seen []sighting
	signed := 0
	for _, h := range w.Heads {
		s3, named := fromS3(h)
		if len(s3) > 0 {
			// Файл из бакета: его содержимое пишет тот, у кого ключи записи, и
			// «сборщик отверг» из него не в счёт (P-100), как и received_at
			// (P-96, sightingsOf): только голова и время версии.
			h.Refused = false
		}
		if VerifyCheckpoint(h.Checkpoint, key) != nil {
			continue
		}
		signed++
		if h.Refused {
			refused = append(refused, h)
			continue
		}
		seen = append(seen, sightingsOf(h, s3, named)...)
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

	// Каждый свидетель закрепляет запись сам: голова не раньше её звена (и не
	// раньше первого звена пакета), которую он получил первой, — переписать
	// цепь после этого значит разойтись с ней. Не первая по номеру: держатель
	// sign.key и ключей свидетеля кладёт позже голову под свободным номером
	// между звеном и ней, и такая голова пришла к свидетелю позже (P-21). При
	// равном времени — бо́льший номер: пакет до него длиннее, и только. У
	// свидетеля без времени — первая по номеру, с заметкой. Пакет обязан дойти
	// до головы каждого свидетеля и сойтись с ней. Одна «первая» на всех
	// свидетелей отдала бы запись голове, которую противник положил к одному
	// свидетелю (S3) раньше, чем другой (сборщик пишет журнал раз в
	// checkpoint_every) записал честную: добавленный свидетель ослаблял бы
	// сверку (P-94).
	lo := max(evLink, first)
	pins := map[string]sighting{}
	for _, s := range seen {
		p, ok := pins[s.witness]
		switch {
		case s.seq < lo:
		case !ok:
			pins[s.witness] = s
		case s.at.IsZero():
			if s.seq < p.seq {
				pins[s.witness] = s
			}
		case s.at.Before(p.at) || s.at.Equal(p.at) && s.seq > p.seq:
			pins[s.witness] = s
		}
	}
	// Самая дальняя голова; на равном номере время — у свидетеля со временем
	// (у самого раннего). Обход — по именам свидетелей, чтобы отчёт не зависел
	// от порядка.
	names := make([]string, 0, len(pins))
	for name := range pins {
		names = append(names, name)
	}
	sort.Strings(names)
	var fix uint64
	var fixAt time.Time
	untimed := false
	for _, name := range names {
		p := pins[name]
		untimed = untimed || p.at.IsZero()
		if p.seq > fix || p.seq == fix && !p.at.IsZero() && (fixAt.IsZero() || p.at.Before(fixAt)) {
			fix, fixAt = p.seq, p.at
		}
	}
	if len(w.pages) > 0 && err == nil {
		err = fmt.Errorf("the S3 versions list %s is one page of several (it has NextToken or IsTruncated): put the whole list in one file, as aws s3api list-object-versions without --max-items writes it", filepath.ToSlash(w.pages[0]))
	}
	// Версия из списка без файла: её голова неизвестна. Лежит она на участке
	// пакета или получена не позже головы, которую этот свидетель S3 получил
	// первой, — сверке её не хватает, и её надо скачать.
	for i, v := range w.Versions {
		if matched[i] || err != nil {
			continue
		}
		p, ok := pins[s3Name(v.list)]
		if first <= v.Size && v.Size <= last || v.Size >= lo && (!ok || !v.At.After(p.at)) {
			err = fmt.Errorf("the S3 versions list names %s version %q, received at %s, and no file in the heads directory is that version (its MD5 is the ETag of a single-part upload, or its name is the version ID with .json): download every version of the heads, each to a file named after its version ID (aws s3api get-object --version-id)", v.Key, v.VersionID, fmtTime(v.At))
		}
	}
	switch {
	case err != nil:
	case len(pins) == 0:
		r.WitnessNone = true
	case untimed:
		// У свидетеля без времени получения закрепляет первая по номеру — с
		// заметкой (P-21), даже если у других время есть (P-94).
		r.WitnessUntimed = true
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
	switch {
	case r.WitnessHead != 0 && len(pins) > 1:
		each := make([]string, 0, len(names))
		for _, name := range names {
			each = append(each, pins[name].String())
		}
		detail = fmt.Sprintf("head %d, the last of the heads each witness received first (%s); %s", r.WitnessHead, strings.Join(each, "; "), counted)
	case r.WitnessHead != 0:
		detail = fmt.Sprintf("head %d, which the witness %s; %s", r.WitnessHead, receivedFirst(fixAt), counted)
	}
	add("the chain in the bundle agrees with the heads the witness saw", err, detail)
}

// sighting — голова, какой её видел один свидетель: witness — кто (откуда
// время и где файл), at — когда он её получил (ноль — без времени).
type sighting struct {
	witness string
	seq     uint64
	at      time.Time
}

// sightingsOf — свидетели головы h, у каждого свои часы. S3 — каждый список
// версий, где нашлась версия файла головы, с её временем (P-99: свидетель —
// список, а не подкаталог: файлы версий раскладывают и по ключам). Файл,
// названный номером версии (named), — скачанная версия, и только. Файл,
// совпавший с версией одними байтами, может быть и своим свидетелем — газетой
// с той же головой, что администратор положил в бакет позже: тогда он ещё и
// голова без времени в своём подкаталоге (P-104). Иначе — сборщик (received_at
// его журнала) или головы без времени, каждые в своём подкаталоге.
func sightingsOf(h PublishedHead, s3 map[string]time.Time, named bool) []sighting {
	seq := h.Checkpoint.Size
	var out []sighting
	for list, at := range s3 {
		out = append(out, sighting{s3Name(list), seq, at})
	}
	if named {
		return out
	}
	file := h.file
	if file == "" {
		file = h.Name
	}
	file = filepath.ToSlash(file)
	dir := path.Dir(file)
	if dir == "." {
		dir = "the heads directory"
	}
	if len(s3) == 0 && !h.Received.IsZero() {
		return []sighting{{collectorOf(dir, path.Base(file)), seq, h.Received}}
	}
	return append(out, sighting{"heads without a time of receipt in " + dir, seq, time.Time{}})
}

// collectorOf — чей файл сборщика. Файлы одного сборщика — журнал, последняя
// голова и расхождения (checkpoints.jsonl, checkpoint.json,
// checkpoints-conflict.jsonl) в одном каталоге, можно с общей приставкой
// имени. Файл с другим именем — свидетель сам по себе: сборщики, сложенные в
// один каталог под своими именами, не сливаются в одного (P-101).
func collectorOf(dir, base string) string {
	// Журнал, который сборщик отложил при запуске (…unverified-<время>), —
	// тоже его (P-105).
	if i := strings.LastIndex(base, ".unverified-"); i > 0 && strings.Trim(base[i+len(".unverified-"):], "0123456789") == "" {
		base = base[:i]
	}
	for _, own := range []string{"checkpoints-conflict.jsonl", "checkpoints.jsonl", "checkpoint.json"} {
		if prefix, ok := strings.CutSuffix(base, own); ok {
			if prefix == "" {
				return "the collector's journal in " + dir
			}
			return "the collector's journal " + prefix + "* in " + dir
		}
	}
	return "the collector's journal " + base + " in " + dir
}

// s3Name — свидетель S3 по файлу его списка версий.
func s3Name(list string) string { return "S3 (versions list " + filepath.ToSlash(list) + ")" }

// listPage — вывод list-object-versions лишь страница списка: CLI с
// --max-items пишет NextToken, API — IsTruncated и NextKeyMarker. Страницы
// одного бакета были бы разными свидетелями, и честный пакет тянули бы до
// первой головы последней страницы (P-105); склеить их проще проверяющему.
func listPage(data []byte) bool {
	var page struct {
		NextToken     string `json:"NextToken"`
		IsTruncated   bool   `json:"IsTruncated"`
		NextKeyMarker string `json:"NextKeyMarker"`
	}
	return json.Unmarshal(data, &page) == nil && (page.NextToken != "" || page.IsTruncated || page.NextKeyMarker != "")
}

func (s sighting) String() string {
	if s.at.IsZero() {
		return fmt.Sprintf("%s: head %d, first by number", s.witness, s.seq)
	}
	return fmt.Sprintf("%s: head %d, received first at %s", s.witness, s.seq, fmtTime(s.at))
}

// receivedFirst — как голова стала закрепляющей: первой полученной (со
// временем) или первой по номеру (времени у голов нет: об этом — заметка).
func receivedFirst(at time.Time) string {
	if at.IsZero() {
		return "saw"
	}
	return "received first, at " + fmtTime(at)
}

// WitnessUntimedNote — у свидетеля без времени получения запись закрепила
// первая по номеру: голову под свободным номером, положенную позже, сверка
// не отличит (P-21).
const WitnessUntimedNote = "heads of a witness at or after this point carry no time of receipt, so for that witness the first by number fixes it: a head added to the witness later under an unused number would be taken instead (P-21). Put the S3 versions list next to the heads (aws s3api list-object-versions … > DIR/versions.json, every version of the heads downloaded), or use a collector's head journal, which carries received_at; otherwise check the receipt times yourself (docs/copy-and-witness.md)"
