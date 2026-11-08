package proof

import (
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
	if r := Verify(honest, tr); !r.Valid() || r.WitnessHead != 4 {
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
