package proof

import (
	"encoding/base64"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
)

// Q-47 (заход 27.10, третий): обход исправления Q-33. Владелец придерживает
// запись abs-core 2, принятую в окне 10:04–10:06, за метку B, которая
// закрывает окно, и за метку C — верхний край пакета по источнику. Затем
// дописывает в конец живой цепи (ничего не переписывая, свидетель видит
// обычное продолжение) копию листа токена A — старой метки, взятой ДО
// записи, — и саму запись, оба звена со временем задним числом. T1 пакета
// записи выбирает хранилище: копия токена A лежит в цепи раньше звена
// записи, её время 10:00 — и время приёма 10:05 проходит, и сверка срока
// идёт от её звена, за звеньями токенов B и C.
//
//	звено 1:  [запуск, abs-core 1 (10:00)]       10:00
//	звено 2:  [хвосты: abs-core 1]               метка A над головой 2 — 10:00
//	звено 3:  [токен A]                          10:00
//	звено 4:  [молчит: other]                    10:07
//	звено 5:  [хвосты: abs-core 1]               метка B над головой 5 — 10:10
//	звено 6:  [токен B]                          10:10
//	звено 7:  [хвосты: abs-core 1]               метка C над головой 7 — 10:11
//	звено 8:  [токен C]                          10:11
//	звено 9:  [копия токена A]                   положено в 10:15, время звена — 10:05:30
//	звено 10: [abs-core 2 (принята 10:05)]       положено в 10:15, время звена — 10:05:30
//	                                             метка D над головой 10 — 10:20
//	звено 11: [токен D]                          10:20
func TestPromiseReplayedLowerToken(t *testing.T) {
	w := newWorld(t)
	salt := func(link uint64) [32]byte { return salt(link, "abs-core") }
	w.now = at(10, 0, 0)
	data1 := sealedBytes(t, 1, w.now, "line 1")
	rec1 := EvidenceLeafLinked(evidence.Header{Source: "abs-core", Seq: 1, ReceivedAt: w.now.UnixNano()}, 1, evidence.Digest(data1), [32]byte{})
	tails := func(link uint64) auditchain.Leaf {
		return TailsLeaf([]Tail{{Source: "abs-core", Seq: 1, Hash: auditchain.LeafHash(rec1), Salt: salt(link)}}, w.now.UnixNano())
	}
	w.wlink(auditchain.Leaf{Type: auditchain.EventStart}, rec1) // 1
	w.wlink(tails(2))                                           // 2
	hA, tA := w.stamp()
	w.wlink(tokenLeaf(hA, tA)) // 3
	w.now = at(10, 7, 0)
	w.wlink(auditchain.Leaf{UnixNano: w.now.UnixNano(), Type: auditchain.EventSilence, Scope: "other"}) // 4
	w.now = at(10, 10, 0)
	w.wlink(tails(5)) // 5
	hB, tB := w.stamp()
	w.wlink(tokenLeaf(hB, tB)) // 6
	w.now = at(10, 11, 0)
	w.wlink(tails(7)) // 7
	hC, tC := w.stamp()
	w.wlink(tokenLeaf(hC, tC)) // 8

	// Придержанная запись и копия токена A — дописаны в 10:15, звенья задним
	// числом.
	w.now = at(10, 5, 30)
	w.wlink(tokenLeaf(hA, tA)) // 9
	held := sealedBytes(t, 2, at(10, 5, 0), "held back")
	heldLeaf := EvidenceLeafLinked(evidence.Header{Source: "abs-core", Seq: 2, ReceivedAt: at(10, 5, 0).UnixNano()}, 2, evidence.Digest(held), auditchain.LeafHash(rec1))
	w.wlink(heldLeaf) // 10
	w.now = at(10, 20, 0)
	hD, tD := w.stamp()
	w.wlink(tokenLeaf(hD, tD)) // 11

	from, to := at(10, 4, 0), at(10, 6, 0)

	// Пакет за окно: участок после головы 2 до звена 6 (токен B) — записи нет.
	wr := VerifyWindow(w.window(2, 6, from, to), w.trust(), from, to)
	if !wr.Valid() {
		t.Fatalf("пакет за окно:\n%s", wr.Text())
	}
	for _, s := range wr.Sources {
		if s.Name == "abs-core" && s.Records > 0 {
			t.Fatalf("пакет за окно показал запись: %+v", s)
		}
	}

	// Пакет по источнику: нижний край — хвосты в звене 2 (A), закрывает B
	// (токен в звене 6), верхний край — хвосты в звене 7 (C). Записей нет.
	lt, ut := FromLeaf(w.leaves[1][0]), FromLeaf(w.leaves[6][0])
	sb := SourceBundle{Version: WindowVersion, Kind: SourceKind, Source: "abs-core", From: from, To: to}
	sb.Lower = SourceEdge{Head: 2, Tails: &lt, Token: w.inclusion(3, 0),
		Open: TailOf(Tail{Source: "abs-core", Seq: 1, Hash: auditchain.LeafHash(rec1), Salt: salt(2)})}
	sb.Upper = SourceEdge{Head: 7, Tails: &ut, Token: w.inclusion(8, 0),
		Open: TailOf(Tail{Source: "abs-core", Seq: 1, Hash: auditchain.LeafHash(rec1), Salt: salt(7)})}
	sb.Closing = w.inclusion(6, 0)
	for _, l := range w.links[1:8] {
		sb.Links = append(sb.Links, FromLink(l))
	}
	l8 := w.links[7]
	sb.Statement = w.signer.Sign(auditchain.Head{Seq: l8.Seq, Hash: auditchain.Hash(l8)}, int(l8.Seq), w.now.Unix())
	sr := VerifySource(sb, w.trust(), from, to)
	if !sr.Valid() || sr.Records != 0 {
		t.Fatalf("пакет по источнику:\n%s", sr.Text())
	}

	// Пакет самой записи: T1 — копия токена A в звене 9.
	b := w.bundle(held, 10, 0, hD, tD, 9)
	r := Verify(b, w.trust())
	if !r.Valid() {
		t.Fatalf("пакет записи с T1 = копия A:\n%s", r.Text())
	}
	digest := evidence.Digest(held)
	p := Promise{Source: "abs-core", Seq: 2, Position: 2, Digest: digest[:], ReceivedAt: at(10, 5, 0).UnixNano(),
		Deadline: at(10, 5, 0).Add(MaxPromiseMMD).UnixNano(), PublicKey: base64.RawStdEncoding.EncodeToString(w.signer.PublicKey())}
	p.Signature = w.signer.SignMessage(PromiseBytes(p))
	if err := VerifyPromise(p, w.signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	perr := CheckPromise(p, r, b, false)

	// Для сравнения: с настоящим T1 (токен A в звене 3) обещание нарушено.
	honest := w.bundle(held, 10, 0, hD, tD, 3)
	hr := Verify(honest, w.trust())
	herr := CheckPromise(p, hr, honest, false)
	t.Logf("пакет за окно: %s; пакет по источнику: %s, записей %d; пакет записи (T1 = копия A, звено 9): %s; обещание: %v; с T1 = A в звене 3: %s, обещание: %v",
		wr.Verdict(), sr.Verdict(), sr.Records, r.Verdict(), perr, hr.Verdict(), herr)
	if perr == nil || herr == nil {
		t.Fatalf("запись придержана за метки B и C (принята 10:05, в цепи — после токена C 10:11), а esverify -promise её срок принимает: с T1 = копия A — %v, с T1 = A — %v", perr, herr)
	}
}

// Q-48 (заход 27.10, третий): обход исправления Q-27. Время приёма записей
// за головой верхней метки сверяется с «последней меткой, чью голову звено
// прошло» (stampBefore) — это последняя ПО МЕСТУ в участке метка с головой
// раньше звена, а не верхняя. Копия токена старой метки A, дописанная за
// токеном верхней метки B (участок продлён на одно звено), становится этой
// меткой для каждого звена участка, и записи окна, спрятанные за голову
// метки B, снова проходят.
//
//	звено 1: [запуск]                         10:00, метка A над головой 1
//	звено 2: [токен A, abs-core 1 (10:02)]    10:02
//	звено 3: [событие]                        10:05 — голова, которую понесут в TSA
//	звено 4: [abs-core 2 (10:07), 3 (10:08)]  10:08 — легли вовремя
//	звено 5: [токен B]                        10:15 — метка B над головой 3
//	звено 6: [копия токена A]                 10:15
func TestWindowReplayedTokenAfterUpperStamp(t *testing.T) {
	w := newWorld(t)
	w.now = at(10, 0, 0)
	w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
	hA, tA := w.stamp()
	w.now = at(10, 2, 0)
	w.wlink(tokenLeaf(hA, tA), rec(t, 1, at(10, 2, 0)))
	w.now = at(10, 5, 0)
	w.wlink(auditchain.Leaf{UnixNano: w.now.UnixNano(), Type: auditchain.EventSilence, Scope: "other"})
	headB := w.head()
	w.now = at(10, 8, 0)
	w.wlink(rec(t, 2, at(10, 7, 0)), rec(t, 3, at(10, 8, 0)))
	w.now = at(10, 15, 0)
	imprint := HeadImprint(headB.Seq, headB.Hash)
	tB, err := w.tsa.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	w.wlink(tokenLeaf(headB.Seq, tB)) // 5
	w.wlink(tokenLeaf(hA, tA))        // 6: копия токена A

	from, to := at(10, 1, 0), at(10, 10, 0)
	honest := VerifyWindow(w.window(1, 5, from, to), w.trust(), from, to)
	r := VerifyWindow(w.window(1, 6, from, to), w.trust(), from, to)
	t.Logf("участок до звена 5: %s; участок до звена 6 (с копией токена A): %s", honest.Verdict(), r.Verdict())
	for _, s := range r.Sources {
		t.Logf("сводка: %s — записей %d, в окне %d, номера %d–%d", s.Name, s.Records, s.InWindow, s.FirstSeq, s.LastSeq)
	}
	if honest.Valid() {
		t.Fatalf("без копии токена пакет прошёл:\n%s", honest.Text())
	}
	if r.Valid() {
		t.Fatalf("записи 2 и 3 (приняты 10:07 и 10:08, в окне 10:01–10:10, легли в цепь вовремя) спрятаны за голову верхней метки B, пакет за окно проходит:\n%s", r.Text())
	}
}
