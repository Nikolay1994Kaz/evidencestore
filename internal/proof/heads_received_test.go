package proof

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// P-21: улику закрепляет голова свидетеля не раньше её звена, которую
// свидетель получил первой, а не первая по номеру. Держатель sign.key и
// ключей записи к свидетелю (это администратор хранилища: хранилище само
// пишет головы свидетелю) переписывает запись, подписывает голову новой цепи
// и кладёт её к свидетелю новым объектом под свободным номером между звеном
// записи и честной головой. Object Lock этого не запрещает. Такая голова
// пришла к свидетелю позже честной, и время версии в S3 это показывает.

// s3Object — версия объекта головы у свидетеля S3: файл, как его скачал
// проверяющий, и запись о ней в списке версий.
type s3Object struct {
	key, vid, file string
	data           []byte
	at             time.Time
	etag           string // пусто — MD5 файла, как у записи одним PUT
}

func headObject(t *testing.T, c Checkpoint, vid string, at time.Time) s3Object {
	t.Helper()
	data, err := c.JSON()
	if err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("witness/heads/%020d.json", c.Size)
	return s3Object{key: key, vid: vid, file: key, data: data, at: at}
}

// s3Witness — каталог голов, как его собирает проверяющий: файл на каждую
// версию и, если list, вывод aws s3api list-object-versions (CLI v2: время с
// «+00:00»).
func s3Witness(t *testing.T, list bool, objs ...s3Object) *Witness {
	t.Helper()
	w := &Witness{}
	var vs []map[string]any
	for _, o := range objs {
		if o.data != nil {
			w.AddFile(o.file, o.data)
		}
		etag := o.etag
		if etag == "" {
			sum := md5.Sum(o.data)
			etag = hex.EncodeToString(sum[:])
		}
		vs = append(vs, map[string]any{"Key": o.key, "VersionId": o.vid, "ETag": `"` + etag + `"`,
			"LastModified": o.at.UTC().Format("2006-01-02T15:04:05+00:00"), "IsLatest": true, "Size": len(o.data), "StorageClass": "STANDARD"})
	}
	if list {
		data, err := json.Marshal(map[string]any{"Versions": vs, "DeleteMarkers": []any{}, "RequestCharged": nil})
		if err != nil {
			t.Fatal(err)
		}
		w.AddFile("versions.json", data)
	}
	return w
}

// rewritten — цепь, переписанная со звена 3 записи (как в P-28), и пакет из
// неё: свежая метка над новой головой 3, пакет кончается ею.
func rewritten(t *testing.T, w *world) (*world, Bundle) {
	t.Helper()
	y := &world{t: t, signer: w.signer, tsa: w.tsa, now: w.now.Add(time.Hour)}
	y.links = append([]auditchain.Record(nil), w.links[:2]...)
	y.leaves = append([][]auditchain.Leaf(nil), w.leaves[:2]...)
	forged := sealedBytes(t, 2, time.Date(2026, 10, 3, 10, 0, 3, 0, time.UTC), "forged")
	y.wlink(w.leaves[2][0], evLeaf(t, forged, 2))
	h3, fresh := y.stamp()
	b := Bundle{Version: Version, Evidence: forged, Inclusion: y.inclusion(3, 1)}
	b.Upper = &Upper{HeadSeq: h3, Token: fresh}
	b.Links = []Link{FromLink(y.links[2])}
	b.Frontier = y.frontier(3)
	b.Checkpoint = y.checkpoint(3)
	return y, b
}

// ⭐ P-21. Честные головы 4 и 5 у свидетеля, запись переписана, голова 3 новой
// цепи положена к свидетелю через час. Без списка версий сверка берёт первую
// по номеру — подложенную — и пакет проходит, но отчёт говорит, что времени
// получения нет. Со списком версий запись закрепляет голова 4, полученная
// первой: пакет из переписанной цепи до неё не доходит, а дойди он — не
// сойдётся.
func TestWitnessFirstReceivedFixes(t *testing.T) {
	w, honest := standard(t, nil) // звенья 1–5, запись в звене 3, пакет до головы 5
	y, forged := rewritten(t, w)
	t4, t5 := w.now.Add(time.Minute), w.now.Add(2*time.Minute)
	objs := []s3Object{
		headObject(t, w.checkpoint(4), "v-4", t4),
		headObject(t, w.checkpoint(5), "v-5", t5),
		headObject(t, y.checkpoint(3), "v-3", y.now), // подложена через час
	}
	tr := w.trust()

	tr.Witness = s3Witness(t, false, objs...)
	r := Verify(forged, tr)
	if !r.Valid() || r.WitnessHead != 3 || !r.WitnessUntimed || !strings.Contains(strings.Join(r.Notes(), "\n"), WitnessUntimedNote) {
		t.Fatalf("без списка версий — первая по номеру, с замечанием:\n%s", r.Text())
	}

	tr.Witness = s3Witness(t, true, objs...)
	r = Verify(forged, tr)
	if r.Valid() || !failed(r, checkAgrees) || !strings.Contains(r.Text(), "before head 4 the witness received first, at") ||
		!strings.Contains(r.Text(), "proof -to-head 4") {
		t.Fatalf("подложенная голова закрепила переписанную запись:\n%s", r.Text())
	}
	// Пакет из переписанной цепи до головы 4 с ней не сходится.
	y.wlink(w.leaves[3]...)
	long := forged
	long.Links = []Link{FromLink(y.links[2]), FromLink(y.links[3])}
	long.Checkpoint = y.checkpoint(4)
	if r := Verify(long, tr); r.Valid() || !strings.Contains(r.Text(), "differs from head 4 the witness saw") {
		t.Fatalf("переписанная цепь до головы 4:\n%s", r.Text())
	}

	// Честный пакет: закрепляет голова 4, с временем получения.
	tr.Witness = s3Witness(t, true, objs[:2]...)
	r = Verify(honest, tr)
	if !r.Valid() || r.WitnessHead != 4 || r.WitnessUntimed || !r.WitnessReceived.Equal(t4) ||
		!strings.Contains(r.Text(), "head 4, which the witness received first, at") || strings.Contains(strings.Join(r.Notes(), "\n"), WitnessUntimedNote) {
		t.Fatalf("честный пакет со списком версий:\n%s", r.Text())
	}
	// Подложенная голова на участке честного пакета — вторая история, и
	// честный пакет с ней не сходится: провал, как и раньше; время получения
	// этого не смягчает.
	tr.Witness = s3Witness(t, true, objs...)
	if r := Verify(honest, tr); r.Valid() || !failed(r, checkAgrees) {
		t.Fatalf("честный пакет при подложенной голове на его участке:\n%s", r.Text())
	}
}

// Голова, подложенная в ту же секунду, что пришла честная: закрепляет
// бо́льший номер, и переписанная запись не проходит.
func TestWitnessFirstReceivedTie(t *testing.T) {
	w, _ := standard(t, nil)
	y, forged := rewritten(t, w)
	t4 := w.now.Add(time.Minute)
	tr := w.trust()
	tr.Witness = s3Witness(t, true, headObject(t, w.checkpoint(4), "v-4", t4), headObject(t, y.checkpoint(3), "v-3", t4))
	if r := Verify(forged, tr); r.Valid() || !strings.Contains(r.Text(), "proof -to-head 4") {
		t.Fatalf("подложенная в ту же секунду:\n%s", r.Text())
	}
}

// Честное хранилище может отдать голову под меткой позже следующей текущей
// (Q-06): голова 5 пришла раньше 4. Закрепляет 5, полученная первой, — пакет до
// 5 проходит; пакет, который кончается 4, просят длиннее.
func TestWitnessHonestOutOfOrder(t *testing.T) {
	w, honest := standard(t, nil)
	tr := w.trust()
	tr.Witness = s3Witness(t, true,
		headObject(t, w.checkpoint(4), "v-4", w.now.Add(2*time.Minute)),
		headObject(t, w.checkpoint(5), "v-5", w.now.Add(time.Minute)))
	if r := Verify(honest, tr); !r.Valid() || r.WitnessHead != 5 {
		t.Fatalf("голова 5 пришла раньше 4:\n%s", r.Text())
	}
}

// Список версий называет версию, которой нет в каталоге: сверке её не
// хватает — неполный каталог дал бы подложенной голове закрепить запись.
// Версия, чей ETag не MD5 (SSE-KMS), находит файл по номеру версии в имени.
func TestWitnessVersionsMatchFiles(t *testing.T) {
	w, honest := standard(t, nil)
	tr := w.trust()
	h4 := headObject(t, w.checkpoint(4), "v-4", w.now.Add(time.Minute))
	missing := h4
	missing.data = nil // в каталоге нет
	tr.Witness = s3Witness(t, true, missing, headObject(t, w.checkpoint(5), "v-5", w.now.Add(2*time.Minute)))
	tr.Witness.Versions[0].ETag = "d41d8cd98f00b204e9800998ecf8427e"
	if r := Verify(honest, tr); r.Valid() || !strings.Contains(r.Text(), `names witness/heads/00000000000000000004.json version "v-4"`) ||
		!strings.Contains(r.Text(), "download every version of the heads") {
		t.Fatalf("версия без файла:\n%s", r.Text())
	}

	kms := h4
	kms.etag = "0123456789abcdef0123456789abcdef-kms"
	kms.file = "versions/v-4.json"
	tr.Witness = s3Witness(t, true, kms)
	if r := Verify(honest, tr); !r.Valid() || r.WitnessHead != 4 || !r.WitnessReceived.Equal(h4.at) {
		t.Fatalf("версия по номеру в имени файла:\n%s", r.Text())
	}
	// Та же голова дважды (повторная запись): время — первой версии.
	again := h4
	again.vid, again.at = "v-4b", h4.at.Add(time.Hour)
	tr.Witness = s3Witness(t, true, again, h4)
	if r := Verify(honest, tr); !r.Valid() || !r.WitnessReceived.Equal(h4.at) {
		t.Fatalf("две версии одной головы:\n%s", r.Text())
	}
}

// P-93: поверх головы 5 положили мусор новой версией (Object Lock этого не
// запрещает), и проверяющий скачал все версии. Версия, нашедшая свой файл, —
// не неизвестная, хоть файл и не голова: честный пакет проходит. Не скачана —
// неизвестна, и сверка просит её скачать.
func TestWitnessJunkVersion(t *testing.T) {
	w, honest := standard(t, nil)
	tr := w.trust()
	h4 := headObject(t, w.checkpoint(4), "v-4", w.now.Add(time.Minute))
	h5 := headObject(t, w.checkpoint(5), "v-5", w.now.Add(2*time.Minute))
	junk := s3Object{key: h5.key, vid: "j-5", file: "versions/j-5.json", data: []byte("not a head"), at: w.now.Add(time.Hour),
		etag: "0123456789abcdef0123456789abcdef-kms"} // находит файл только по номеру версии в имени
	tr.Witness = s3Witness(t, true, h4, h5, junk)
	if r := Verify(honest, tr); !r.Valid() || r.WitnessHead != 4 || !r.WitnessReceived.Equal(h4.at) {
		t.Fatalf("мусор поверх головы 5, файл по номеру версии:\n%s", r.Text())
	}
	junk.file, junk.etag = "junk.json", "" // только по ETag
	tr.Witness = s3Witness(t, true, h4, h5, junk)
	if r := Verify(honest, tr); !r.Valid() || r.WitnessHead != 4 || !strings.Contains(r.Text(), "2 heads signed with the store key, 1 of 3 entries are not such heads") {
		t.Fatalf("мусор поверх головы 5, файл по ETag:\n%s", r.Text())
	}
	junk.data = nil
	tr.Witness = s3Witness(t, true, h4, h5, junk)
	if r := Verify(honest, tr); r.Valid() || !strings.Contains(r.Text(), `version "j-5"`) || !strings.Contains(r.Text(), "download every version of the heads") {
		t.Fatalf("мусор поверх головы 5 не скачан:\n%s", r.Text())
	}
}

// Журналы голов сборщиков несут received_at. Новый сборщик берёт первую
// голову на веру и принял голову переписанной цепи через час; честный сборщик
// получил головы 4 и 5 раньше — закрепляют они.
func TestWitnessCollectorReceivedAt(t *testing.T) {
	w, _ := standard(t, nil)
	y, forged := rewritten(t, w)
	line := func(c Checkpoint, at time.Time) []byte {
		data, err := json.Marshal(map[string]any{"received_at": at, "checkpoint": c})
		if err != nil {
			t.Fatal(err)
		}
		return append(data, '\n')
	}
	a := append(line(w.checkpoint(4), w.now), line(w.checkpoint(5), w.now.Add(time.Minute))...)
	tr := w.trust()
	tr.Witness = &Witness{}
	tr.Witness.AddFile("A/checkpoints.jsonl", a)
	tr.Witness.AddFile("C/checkpoints.jsonl", line(y.checkpoint(3), y.now))
	if r := Verify(forged, tr); r.Valid() || !strings.Contains(r.Text(), "proof -to-head 4") {
		t.Fatalf("голова нового сборщика закрепила переписанную запись:\n%s", r.Text())
	}
	// Одна голова из двух мест: в журнале — позже, в S3 — раньше. Время —
	// самое раннее, иначе подложенная голова 3 пришла бы «первой».
	tr.Witness = &Witness{}
	tr.Witness.AddFile("A/checkpoints.jsonl", line(w.checkpoint(4), w.now.Add(2*time.Hour)))
	s3 := s3Witness(t, true, headObject(t, w.checkpoint(4), "v-4", w.now.Add(time.Minute)), headObject(t, y.checkpoint(3), "v-3", y.now))
	tr.Witness.Heads = append(tr.Witness.Heads, s3.Heads...)
	tr.Witness.Versions = s3.Versions
	if r := Verify(forged, tr); r.Valid() || !strings.Contains(r.Text(), "proof -to-head 4") {
		t.Fatalf("время одной головы из двух мест:\n%s", r.Text())
	}
}

// Вывод list-object-versions: CLI v1 и v2, ключ с префиксом; ключи не голов
// пропускаются; файл без массива Versions — не список.
func TestParseHeadVersions(t *testing.T) {
	data := []byte(`{"Versions":[
		{"Key":"w/heads/00000000000000000005.json","VersionId":"a","ETag":"\"ab\"","LastModified":"2026-11-08T10:00:00.000Z"},
		{"Key":"heads/7.json","VersionId":"b","ETag":"\"cd\"","LastModified":"2026-11-08T10:01:00+00:00"},
		{"Key":"w/xheads/5.json","LastModified":"2026-11-08T10:00:00Z"},
		{"Key":"w/heads/5.json.bak","LastModified":"2026-11-08T10:00:00Z"},
		{"Key":"w/heads/abc.json","LastModified":"2026-11-08T10:00:00Z"},
		{"Key":"w/heads/9.json","LastModified":"вчера"}
	],"DeleteMarkers":[]}`)
	vs, ok := parseHeadVersions(data)
	if !ok || len(vs) != 2 || vs[0].Size != 5 || vs[0].ETag != "ab" || vs[1].Size != 7 || vs[1].VersionID != "b" ||
		!vs[1].At.Equal(time.Date(2026, 11, 8, 10, 1, 0, 0, time.UTC)) {
		t.Fatalf("версии: %+v", vs)
	}
	for _, other := range []string{`{"checkpoint":{}}`, `[]`, `not json`} {
		if _, ok := parseHeadVersions([]byte(other)); ok {
			t.Fatalf("%s — список версий", other)
		}
	}
}

// ⭐ P-94: каждый свидетель закрепляет запись сам. Хранилище придержало честные
// головы для S3, переписало запись 3 и отдало S3 голову 3 новой цепи через
// минуту. Сборщик получил честную голову 4 в ответе через секунды, а в журнал
// записал её в свой срок (checkpoint_every). Одна «первая» на всех взяла бы
// голову S3, и подделка прошла бы, хотя со сборщиком отдельно она не проходит:
// пакет обязан дойти до головы каждого свидетеля.
func TestWitnessEachFixesOnItsOwn(t *testing.T) {
	w, honest := standard(t, nil)
	y, forged := rewritten(t, w)
	line := func(c Checkpoint, at time.Time) []byte {
		data, err := json.Marshal(map[string]any{"received_at": at, "checkpoint": c})
		if err != nil {
			t.Fatal(err)
		}
		return append(data, '\n')
	}
	dir := func(s3 *Witness, files map[string][]byte) *Witness {
		wt := &Witness{}
		for name, data := range files {
			wt.AddFile(name, data)
		}
		if s3 != nil {
			wt.Heads = append(wt.Heads, s3.Heads...)
			wt.Versions = s3.Versions
		}
		return wt
	}
	tr := w.trust()
	late4 := line(w.checkpoint(4), w.now.Add(9*time.Minute))
	s3 := s3Witness(t, true, headObject(t, y.checkpoint(3), "v-3", w.now.Add(time.Minute)))
	for _, name := range []string{"A/checkpoints.jsonl", "witness/heads/checkpoints.jsonl", "checkpoints.jsonl"} { // в своём подкаталоге, рядом с файлами S3, в корне
		tr.Witness = dir(s3, map[string][]byte{name: late4})
		if r := Verify(forged, tr); r.Valid() || !strings.Contains(r.Text(), "proof -to-head 4") {
			t.Fatalf("%s: голова S3 новой цепи отменила голову сборщика:\n%s", name, r.Text())
		}
	}
	// Новый сборщик взял голову новой цепи на веру и записал её раньше, чем
	// честный записал свою.
	tr.Witness = dir(nil, map[string][]byte{"A/checkpoints.jsonl": late4, "C/checkpoints.jsonl": line(y.checkpoint(3), w.now.Add(5*time.Minute))})
	if r := Verify(forged, tr); r.Valid() || !strings.Contains(r.Text(), "proof -to-head 4") {
		t.Fatalf("новый сборщик отменил честного:\n%s", r.Text())
	}
	// Честный пакет: S3 получил голову 4 через минуту, сборщик записал голову 5
	// через девять. Пакет доходит до 5, отчёт называет обоих.
	tr.Witness = dir(s3Witness(t, true, headObject(t, w.checkpoint(4), "v-4", w.now.Add(time.Minute))),
		map[string][]byte{"A/checkpoints.jsonl": line(w.checkpoint(5), w.now.Add(9*time.Minute))})
	r := Verify(honest, tr)
	if !r.Valid() || r.WitnessHead != 5 || !r.WitnessReceived.Equal(w.now.Add(9*time.Minute)) ||
		!strings.Contains(r.Text(), "head 5, the last of the heads each witness received first (S3 (versions list versions.json): head 4, received first at") ||
		!strings.Contains(r.Text(), "the collector's journal in A: head 5, received first at") {
		t.Fatalf("честный пакет, два свидетеля:\n%s", r.Text())
	}
	// Версия S3 без файла, полученная после головы, которую S3 получил первой,
	// и вне пакета, закрепления не меняет: скачивать её не нужно.
	extra := s3Witness(t, true, headObject(t, w.checkpoint(4), "v-4", w.now.Add(time.Minute)),
		s3Object{key: "witness/heads/00000000000000000006.json", vid: "v-6", at: w.now.Add(3 * time.Minute)})
	tr.Witness = dir(extra, map[string][]byte{"A/checkpoints.jsonl": line(w.checkpoint(5), w.now.Add(9*time.Minute))})
	if r := Verify(honest, tr); !r.Valid() || r.WitnessHead != 5 {
		t.Fatalf("версия S3 после первой головы S3:\n%s", r.Text())
	}
}

// ⭐ P-94: часы разных свидетелей не сравниваются. (1) Часы сборщика C
// отстают на 10 минут, а он принял голову 3 новой цепи (новый или державший
// голову старше звена записи): по его часам она «пришла» раньше, чем S3
// получил честную голову 4. (2) Газета без времени держит честную голову 4, а
// у S3 только голова 3 новой цепи: свидетель без времени закрепляет по
// номеру. (3) S3 без списка версий и новый сборщик C с головой новой цепи: S3
// держит по номеру; а если в S3 подложена и голова 3, пакет проходит, и отчёт
// говорит, что один свидетель закрепил по номеру, хотя у другого время есть.
func TestWitnessClocksNotCompared(t *testing.T) {
	w, _ := standard(t, nil)
	y, forged := rewritten(t, w)
	line := func(c Checkpoint, at time.Time) []byte {
		data, err := json.Marshal(map[string]any{"received_at": at, "checkpoint": c})
		if err != nil {
			t.Fatal(err)
		}
		return append(data, '\n')
	}
	t4, t5 := w.now.Add(time.Minute), w.now.Add(2*time.Minute)
	h4, h5 := headObject(t, w.checkpoint(4), "v-4", t4), headObject(t, w.checkpoint(5), "v-5", t5)
	tr := w.trust()

	tr.Witness = s3Witness(t, true, h4, h5)
	tr.Witness.AddFile("C/checkpoints.jsonl", line(y.checkpoint(3), t4.Add(5*time.Minute-10*time.Minute)))
	if r := Verify(forged, tr); r.Valid() || !strings.Contains(r.Text(), "proof -to-head 4") {
		t.Fatalf("(1) часы сборщика отстают:\n%s", r.Text())
	}

	statement, err := w.checkpoint(4).JSON()
	if err != nil {
		t.Fatal(err)
	}
	tr.Witness = s3Witness(t, true, headObject(t, y.checkpoint(3), "v-3", y.now))
	tr.Witness.AddFile("mail/statement.json", statement)
	if r := Verify(forged, tr); r.Valid() || !strings.Contains(r.Text(), "proof -to-head 4") {
		t.Fatalf("(2) газета без времени:\n%s", r.Text())
	}

	tr.Witness = s3Witness(t, false, h4, h5)
	tr.Witness.AddFile("C/checkpoints.jsonl", line(y.checkpoint(3), y.now))
	if r := Verify(forged, tr); r.Valid() || !strings.Contains(r.Text(), "proof -to-head 4") {
		t.Fatalf("(3) S3 без списка:\n%s", r.Text())
	}
	tr.Witness = s3Witness(t, false, h4, h5, headObject(t, y.checkpoint(3), "v-3", y.now))
	tr.Witness.AddFile("C/checkpoints.jsonl", line(y.checkpoint(3), y.now))
	r := Verify(forged, tr)
	if !r.Valid() || !r.WitnessUntimed || !strings.Contains(strings.Join(r.Notes(), "\n"), WitnessUntimedNote) ||
		!strings.Contains(r.Text(), "heads without a time of receipt in witness/heads: head 3, first by number") {
		t.Fatalf("(3) S3 без списка с подложенной головой:\n%s", r.Text())
	}
}

// ⭐ P-96: содержимое объекта S3 пишет тот, у кого ключи записи. Строка в
// форме журнала сборщика с ранним received_at, положенная в бакет, — не время
// получения: голова из неё получает время версии. Мусор из двух строк,
// скачанный по версии, — известная версия, как и мусор в одну (P-93).
func TestWitnessS3ObjectTimes(t *testing.T) {
	w, honest := standard(t, nil)
	y, forged := rewritten(t, w)
	line := func(c Checkpoint, at time.Time) []byte {
		data, err := json.Marshal(map[string]any{"received_at": at, "checkpoint": c})
		if err != nil {
			t.Fatal(err)
		}
		return append(data, '\n')
	}
	t4, t5 := w.now.Add(time.Minute), w.now.Add(2*time.Minute)
	h4, h5 := headObject(t, w.checkpoint(4), "v-4", t4), headObject(t, w.checkpoint(5), "v-5", t5)
	tr := w.trust()
	for _, lines := range []int{1, 2} {
		planted := s3Object{key: "witness/heads/00000000000000000003.json", vid: "v-3", file: "v-3.json",
			data: bytes.Repeat(line(y.checkpoint(3), w.now), lines), at: y.now}
		tr.Witness = s3Witness(t, true, h4, h5, planted)
		if r := Verify(forged, tr); r.Valid() || !strings.Contains(r.Text(), "proof -to-head 4") {
			t.Fatalf("received_at в объекте S3, строк %d:\n%s", lines, r.Text())
		}
	}
	// Копия честной головы 4 строкой журнала с received_at раньше всех: время
	// головы 4 — всё равно время её версии.
	early := s3Object{key: h4.key, vid: "v-4b", file: "v-4b.json", data: line(w.checkpoint(4), w.now.Add(-time.Hour)), at: t5.Add(time.Hour)}
	tr.Witness = s3Witness(t, true, h4, h5, early)
	if r := Verify(honest, tr); !r.Valid() || r.WitnessHead != 4 || !r.WitnessReceived.Equal(t4) {
		t.Fatalf("received_at в объекте S3 дал голове время:\n%s", r.Text())
	}
	junk := s3Object{key: h5.key, vid: "j-5", file: "j-5.json", data: []byte("junk\nmore junk\n"), at: t5.Add(time.Hour)}
	tr.Witness = s3Witness(t, true, h4, h5, junk)
	if r := Verify(honest, tr); !r.Valid() || r.WitnessHead != 4 {
		t.Fatalf("мусор из двух строк поверх головы 5:\n%s", r.Text())
	}
}

// ⭐ P-95: номер версии — имя файла без «.json», точно. «null» (версии,
// записанные до включения версий) по имени не ищется: он у всех таких версий
// один. Номер с «/» (у AWS бывает) — путь файла в каталоге. Подстрока номера
// в имени — не номер.
func TestWitnessVersionNames(t *testing.T) {
	w, honest := standard(t, nil)
	tr := w.trust()
	const kms = "0123456789abcdef0123456789abcdef-kms" // ETag не MD5: только по имени
	h4 := headObject(t, w.checkpoint(4), "null", w.now.Add(time.Minute))
	h5 := headObject(t, w.checkpoint(5), "null", w.now.Add(2*time.Minute))
	h4.data, h4.etag, h5.file = nil, kms, "null.json" // голова 4 не скачана
	tr.Witness = s3Witness(t, true, h4, h5)
	if r := Verify(honest, tr); r.Valid() || !strings.Contains(r.Text(), `version "null"`) {
		t.Fatalf("версия null без файла сочтена скачанной:\n%s", r.Text())
	}
	slash := headObject(t, w.checkpoint(4), "3/L4kq+tJ", w.now.Add(time.Minute))
	slash.etag, slash.file = kms, "3/L4kq+tJ.json"
	tr.Witness = s3Witness(t, true, slash)
	if r := Verify(honest, tr); !r.Valid() || r.WitnessHead != 4 {
		t.Fatalf("номер версии с «/»:\n%s", r.Text())
	}
	sub := headObject(t, w.checkpoint(4), "v-4", w.now.Add(time.Minute))
	sub.etag, sub.file = kms, "x-v-4.json"
	tr.Witness = s3Witness(t, true, sub)
	if r := Verify(honest, tr); r.Valid() || !strings.Contains(r.Text(), `version "v-4"`) {
		t.Fatalf("номер версии подстрокой имени:\n%s", r.Text())
	}
}

// P-95: файл находит свою версию за один поиск. Поверх головы 9 — 40 000
// версий мусора, все скачаны: сверка — доли секунды, а перебор списка на
// каждый файл шёл здесь 23 секунды, на год голов раз в минуту — час с лишним.
func TestWitnessVersionsLinear(t *testing.T) {
	w, honest := standard(t, nil)
	tr := w.trust()
	objs := []s3Object{headObject(t, w.checkpoint(4), "v-4", w.now.Add(time.Minute))}
	for i := range 40000 {
		objs = append(objs, s3Object{key: "witness/heads/00000000000000000009.json", vid: fmt.Sprintf("j%06d", i),
			file: fmt.Sprintf("j%06d.json", i), data: []byte(fmt.Sprintf("junk %d", i)), at: w.now.Add(time.Hour)})
	}
	tr.Witness = s3Witness(t, true, objs...)
	start := time.Now()
	r := Verify(honest, tr)
	if d := time.Since(start); !r.Valid() || r.WitnessHead != 4 || d > 5*time.Second {
		t.Fatalf("40 000 версий: %v\n%s", d, r.Text())
	}
}

// Версия без файла на первом звене пакета (голова под T1) валит сверку: под
// этим номером у свидетеля может лежать вторая голова (тестировщик T, 08.11).
func TestWitnessMissingVersionAtFirstLink(t *testing.T) {
	w, honest := standard(t, nil) // пакет — звенья 1–5
	tr := w.trust()
	h1 := headObject(t, w.checkpoint(1), "v-1", w.now.Add(-time.Minute))
	missing := h1
	missing.vid, missing.data, missing.etag = "v-1b", nil, "00112233445566778899aabbccddeeff"
	tr.Witness = s3Witness(t, true, h1, headObject(t, w.checkpoint(4), "v-4", w.now.Add(time.Minute)), missing)
	if r := Verify(honest, tr); r.Valid() || !strings.Contains(r.Text(), `version "v-1b"`) {
		t.Fatalf("версия без файла на первом звене пакета:\n%s", r.Text())
	}
}

// Со списком версий, но без головы S3 со временем не раньше звена записи
// версия без файла дальше пакета — тоже «скачай»; и в ту же секунду, что
// голова, которую S3 получил первой, — тоже (у AWS время до секунды).
func TestWitnessMissingVersionBounds(t *testing.T) {
	w, honest := standard(t, nil)
	tr := w.trust()
	t4 := w.now.Add(time.Minute)
	h7 := s3Object{key: "witness/heads/00000000000000000007.json", vid: "v-7", at: t4, etag: "00112233445566778899aabbccddeeff"}
	tr.Witness = s3Witness(t, true, headObject(t, w.checkpoint(2), "v-2", w.now.Add(-time.Minute)), h7)
	if r := Verify(honest, tr); r.Valid() || !strings.Contains(r.Text(), `version "v-7"`) {
		t.Fatalf("версия без файла дальше пакета, головы со временем нет:\n%s", r.Text())
	}
	tr.Witness = s3Witness(t, true, headObject(t, w.checkpoint(4), "v-4", t4), h7)
	if r := Verify(honest, tr); r.Valid() || !strings.Contains(r.Text(), `version "v-7"`) {
		t.Fatalf("версия без файла в ту же секунду, что голова 4:\n%s", r.Text())
	}
}

// received_at сборщика — ровно то, что в журнале (тестировщик T, 08.11).
func TestWitnessCollectorTimeExact(t *testing.T) {
	w, honest := standard(t, nil)
	tA := w.now.Add(10 * time.Minute)
	line := func(c Checkpoint, at time.Time) []byte {
		data, err := json.Marshal(map[string]any{"received_at": at, "checkpoint": c})
		if err != nil {
			t.Fatal(err)
		}
		return append(data, '\n')
	}
	tr := w.trust()
	tr.Witness = &Witness{}
	tr.Witness.AddFile("A/checkpoints.jsonl", append(line(w.checkpoint(4), tA), line(w.checkpoint(5), tA.Add(time.Minute))...))
	if r := Verify(honest, tr); !r.Valid() || r.WitnessHead != 4 || !r.WitnessReceived.Equal(tA) {
		t.Fatalf("время из журнала сборщика: %v\n%s", r.WitnessReceived, r.Text())
	}
}

// Формы списка версий: префикс свидетеля сам с «heads/» (номер — из
// последнего), вывод без DeleteMarkers, список из двух страниц (тестировщик
// T, 08.11).
func TestParseHeadVersionsShapes(t *testing.T) {
	vs, ok := parseHeadVersions([]byte(`{"Versions":[
		{"Key":"heads/heads/00000000000000000005.json","VersionId":"a","ETag":"\"ab\"","LastModified":"2026-11-08T10:00:00+00:00"},
		{"Key":"myheads/heads/00000000000000000006.json","VersionId":"b","ETag":"\"cd\"","LastModified":"2026-11-08T10:01:00+00:00"}
	],"RequestCharged":null}`))
	if !ok || len(vs) != 2 || vs[0].Size != 5 || vs[1].Size != 6 {
		t.Fatalf("префикс с heads/, без DeleteMarkers: %v %+v", ok, vs)
	}
	w := &Witness{}
	w.AddFile("versions-1.json", []byte(`{"Versions":[{"Key":"w/heads/1.json","VersionId":"a","ETag":"\"ab\"","LastModified":"2026-11-08T10:00:00Z"}],"NextToken":"x"}`))
	w.AddFile("versions-2.json", []byte(`{"Versions":[{"Key":"w/heads/2.json","VersionId":"b","ETag":"\"cd\"","LastModified":"2026-11-08T10:01:00Z"}]}`))
	if len(w.Versions) != 2 {
		t.Fatalf("две страницы списка: %+v", w.Versions)
	}
}

// Пакеты за окно и по источнику несут время закрепляющей головы и заметку
// без времени, как пакет одной улики; голова ровно на звене токена верхней
// метки закрепляет (исследователь R1 и тестировщик T, 08.11).
func TestWindowSourceWitnessReceived(t *testing.T) {
	ww := windowWorld(t, nil, nil) // звенья 1..3, StretchEnd = 3
	wb := ww.window(1, 3, at(10, 4, 0), at(10, 6, 0))
	sw := newSrcWorld(t, srcOpts{})
	sb := sw.bundle(at(10, 4, 0), at(10, 6, 0))
	te := at(10, 30, 0)
	for _, list := range []bool{true, false} {
		tr := ww.trust()
		tr.Witness = s3Witness(t, list, headObject(t, ww.checkpoint(3), "v-3", te))
		r := VerifyWindow(wb, tr, time.Time{}, time.Time{})
		if !r.Valid() || r.WitnessHead != 3 || r.WitnessUntimed == list || r.WitnessReceived.Equal(te) != list ||
			strings.Contains(strings.Join(r.Notes(), "\n"), WitnessUntimedNote) == list {
			t.Fatalf("окно, список версий %v:\n%s", list, r.Text())
		}
		end := sb.Checkpoint.Size
		tr = sw.trust()
		tr.Witness = s3Witness(t, list, headObject(t, sw.checkpoint(end), "v-e", te))
		sr := VerifySource(sb, tr, time.Time{}, time.Time{})
		if !sr.Valid() || sr.WitnessHead != end || sr.WitnessUntimed == list || sr.WitnessReceived.Equal(te) != list ||
			strings.Contains(strings.Join(sr.Notes(), "\n"), WitnessUntimedNote) == list {
			t.Fatalf("источник, список версий %v:\n%s", list, sr.Text())
		}
	}
}

// ⭐ P-99: свидетель S3 — его список версий, а не подкаталог. Проверяющий
// разложил версии по ключам (DIR/<ключ>/<номер версии>.json): подкаталог на
// ключ стал бы «свидетелем», и пакет пришлось бы тянуть до последней головы
// бакета. Два бакета — два списка — два свидетеля: часы одного S3 с часами
// другого не сравниваются (у второго, с отстающими часами, первой «пришла»
// голова новой цепи).
func TestWitnessS3ByVersionsList(t *testing.T) {
	w, honest := standard(t, nil)
	y, forged := rewritten(t, w)
	w.wlink(auditchain.Leaf{Type: auditchain.EventGap, Scope: "abs-core"}) // звено 6 после пакета
	tr := w.trust()
	var byKey []s3Object
	for i, seq := range []uint64{4, 5, 6} {
		o := headObject(t, w.checkpoint(seq), fmt.Sprintf("v-%d", seq), w.now.Add(time.Duration(i+1)*time.Minute))
		o.file = o.key + "/" + o.vid + ".json"
		byKey = append(byKey, o)
	}
	tr.Witness = s3Witness(t, true, byKey...)
	if r := Verify(honest, tr); !r.Valid() || r.WitnessHead != 4 || !r.WitnessReceived.Equal(byKey[0].at) {
		t.Fatalf("версии по ключам:\n%s", r.Text())
	}
	second := s3Witness(t, true, headObject(t, y.checkpoint(3), "u-3", w.now)) // второй бакет, часы отстают
	for i := range second.Versions {
		second.Versions[i].list = "bucket-2/versions.json"
	}
	tr.Witness = s3Witness(t, true, byKey[:2]...)
	tr.Witness.Heads = append(tr.Witness.Heads, second.Heads...)
	tr.Witness.Versions = append(tr.Witness.Versions, second.Versions...)
	if r := Verify(forged, tr); r.Valid() || !strings.Contains(r.Text(), "proof -to-head 4") {
		t.Fatalf("два бакета:\n%s", r.Text())
	}
}

// ⭐ P-100: объект в бакете в форме строки файла расхождений сборщика
// объявляет честную голову 4 «отвергнутой». Содержимое объекта пишет тот, у
// кого ключи записи: голова из него — просто голова со временем версии, и
// честный пакет проходит.
func TestWitnessS3ObjectNotRefused(t *testing.T) {
	w, honest := standard(t, nil)
	t4, t5 := w.now.Add(time.Minute), w.now.Add(2*time.Minute)
	line, err := json.Marshal(map[string]any{"received_at": w.now, "reason": "x", "previous": w.checkpoint(2), "checkpoint": w.checkpoint(4), "consistency": nil})
	if err != nil {
		t.Fatal(err)
	}
	fake := s3Object{key: "witness/heads/00000000000000000009.json", vid: "v-9", file: "v-9.json", data: append(line, '\n'), at: t5.Add(time.Hour)}
	tr := w.trust()
	tr.Witness = s3Witness(t, true, headObject(t, w.checkpoint(4), "v-4", t4), headObject(t, w.checkpoint(5), "v-5", t5), fake)
	if r := Verify(honest, tr); !r.Valid() || r.WitnessHead != 4 || r.WitnessRefused != 0 {
		t.Fatalf("«отвергнутая» голова из объекта S3:\n%s", r.Text())
	}
}

// ⭐ P-101: файлы одного сборщика — журнал, последняя голова и расхождения
// под своими именами (можно с общей приставкой) — один свидетель, и его
// последняя голова пакет не удлиняет. Файлы под другими именами в одном
// каталоге — разные свидетели: сборщик A получил голову новой цепи рано,
// честный B записал голову 4 позже — пакет обязан дойти до 4 (исследователь
// R1, 08.11).
func TestWitnessCollectorFiles(t *testing.T) {
	w, honest := standard(t, nil)
	y, forged := rewritten(t, w)
	line := func(c Checkpoint, at time.Time) []byte {
		data, err := json.Marshal(map[string]any{"received_at": at, "checkpoint": c})
		if err != nil {
			t.Fatal(err)
		}
		return append(data, '\n')
	}
	t4, t5 := w.now.Add(time.Minute), w.now.Add(2*time.Minute)
	journal := append(line(w.checkpoint(4), t4), line(w.checkpoint(5), t5)...)
	tr := w.trust()
	for _, prefix := range []string{"", "A-"} {
		tr.Witness = &Witness{}
		tr.Witness.AddFile("A/"+prefix+"checkpoints.jsonl", journal)
		tr.Witness.AddFile("A/"+prefix+"checkpoint.json", line(w.checkpoint(5), t5)) // последняя голова, как пишет сборщик
		r := Verify(honest, tr)
		if !r.Valid() || r.WitnessHead != 4 || !r.WitnessReceived.Equal(t4) || r.WitnessUntimed {
			t.Fatalf("файлы сборщика %q:\n%s", prefix, r.Text())
		}
	}
	tr.Witness = &Witness{}
	tr.Witness.AddFile("C/a.jsonl", line(y.checkpoint(3), w.now.Add(time.Minute)))
	tr.Witness.AddFile("C/b.jsonl", line(w.checkpoint(4), w.now.Add(5*time.Minute)))
	if r := Verify(forged, tr); r.Valid() || !strings.Contains(r.Text(), "proof -to-head 4") {
		t.Fatalf("два сборщика в одном каталоге:\n%s", r.Text())
	}
}

// Самую дальнюю голову закрепили двое — со временем и без: время в отчёте —
// у того, кто со временем (тестировщик T, 08.11). Газета — та же голова 4 с
// переводом строки в конце: байт в байт с объектом S3 она нашла бы его версию.
func TestWitnessTieTimedUntimed(t *testing.T) {
	w, honest := standard(t, nil)
	t4 := w.now.Add(time.Minute)
	head, err := w.checkpoint(4).JSON()
	if err != nil {
		t.Fatal(err)
	}
	statement := bytes.NewBuffer(append(head, '\n'))
	tr := w.trust()
	for _, order := range []bool{true, false} {
		tr.Witness = &Witness{}
		s3 := s3Witness(t, true, headObject(t, w.checkpoint(4), "v-4", t4))
		if order {
			tr.Witness.AddFile("mail/statement.json", statement.Bytes())
		}
		tr.Witness.Heads = append(tr.Witness.Heads, s3.Heads...)
		tr.Witness.Versions = s3.Versions
		if !order {
			tr.Witness.AddFile("mail/statement.json", statement.Bytes())
		}
		if r := Verify(honest, tr); !r.Valid() || r.WitnessHead != 4 || !r.WitnessReceived.Equal(t4) || !r.WitnessUntimed {
			t.Fatalf("ничья по номеру, порядок %v:\n%s", order, r.Text())
		}
	}
}
