package proof

import (
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// Q-80 (заход 2 нового цикла, 28.10). Запись v0.2.0 (обещание со
// сроком 10 с, часы хоста позади TSA на 30 с) честного хранилища: метка T1
// легла до записи, её время TSA позже времени приёма на 25 с. Лист записи
// пишет тот, кто кладёт её в цепь: v0.2.0 — без ссылки на прежнюю, этот
// выпуск при догоне после падения v0.2.0 или подъёма из его копии — со
// ссылкой. -promise обязан пройти при обоих: README обещает записи v0.2.0
// минуту от времени приёма, и отличить её по формату листа нельзя.
func TestPromiseOldRecordAnyLeaf(t *testing.T) {
	for _, linked := range []bool{false, true} {
		w := newWorld(t)
		w.now = at(9, 59, 30)
		w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
		w.now = at(10, 0, 0)
		h1, tok := w.stamp()
		w.now = at(9, 59, 30)
		w.wlink(tokenLeaf(h1, tok))
		recv := at(9, 59, 35)
		data := sealedBytes(t, 2, recv, "line 2")
		w.now = recv
		w.wlink(j10leaf(t, data, auditchain.Leaf{}, linked))
		w.now = at(10, 10, 0)
		h2, tok2 := w.stamp()
		w.wlink(tokenLeaf(h2, tok2))

		p := j10promise(w, data, recv, 10*time.Second)
		b := w.bundle(data, 3, 0, h2, tok2, 2)
		r := Verify(b, w.trust())
		err := CheckPromise(p, r, b, false)
		t.Logf("лист со ссылкой: %v — пакет %s; -promise: %v", linked, r.Verdict(), err)
		if !r.Valid() || err != nil {
			t.Errorf("честная запись v0.2.0 (срок 10 с), лист со ссылкой: %v — обвинена: %v", linked, err)
		}
	}
}

// Q-80, обратный ход: формат листа выбирает хранилище, поэтому правило от него не
// зависит. Запись этого выпуска (срок 57 с: конфиг пускает от 55 с и двух
// тиков до минуты) лежит за меткой B. B через 58 с после приёма — в пределах
// минуты, -promise проходит при любом листе; через 61 с — позже минуты,
// -promise проваливается при любом листе.
//
//	звено 1: [запуск]                10:00, метка A над головой 1
//	звено 2: [токен A, abs-core 1]   10:02
//	звено 3: [молчит: other]         метка B над головой 3
//	звено 4: [токен B]
//	звено 5: [abs-core 2]            принята 10:05:00, срок 10:05:57
//	звено 6: [токен C]               метка C (10:21) над головой 5
func TestPromiseMinuteWhateverLeaf(t *testing.T) {
	for _, bAt := range []time.Duration{58 * time.Second, 61 * time.Second} {
		for _, linked := range []bool{true, false} {
			w := newWorld(t)
			w.now = at(10, 0, 0)
			w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
			hA, tA := w.stamp()
			w.now = at(10, 2, 0)
			r1 := rec(t, 1, at(10, 2, 0))
			w.wlink(tokenLeaf(hA, tA), r1)
			recv := at(10, 5, 0)
			data := sealedBytes(t, 2, recv, "line 2")
			w.now = at(10, 5, 30)
			w.wlink(auditchain.Leaf{UnixNano: w.now.UnixNano(), Type: auditchain.EventSilence, Scope: "other"})
			w.now = recv.Add(bAt)
			hB, tB := w.stamp()
			w.wlink(tokenLeaf(hB, tB))
			w.wlink(j10leaf(t, data, r1, linked))
			w.now = at(10, 21, 0)
			hC, tC := w.stamp()
			w.wlink(tokenLeaf(hC, tC))

			b := w.bundle(data, 5, 0, hC, tC, 2)
			r := Verify(b, w.trust())
			if !r.Valid() {
				t.Fatalf("пакет не прошёл:\n%s", r.Text())
			}
			err := CheckPromise(j10promise(w, data, recv, 57*time.Second), r, b, false)
			t.Logf("метка B через %s, лист со ссылкой: %v — -promise: %v", bAt, linked, err)
			if late := bAt > MaxPromiseMMD; late != (err != nil) {
				t.Errorf("метка B через %s после приёма, лист со ссылкой: %v: -promise %v", bAt, linked, err)
			}
		}
	}
}
