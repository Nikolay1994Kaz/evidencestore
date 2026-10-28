package proof

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
)

// Судья захода 1 нового цикла (28.10): правило сверки обещания не должно
// зависеть от того, что пишет владелец или кто угодно по дороге, — ни от
// неподписанного поля "v" пакета, ни от формата листа записи (его пишет
// хранилище владельца, и лист без ссылки на прежнюю запись он выдаст для
// любой своей записи).

// j10stretch — листья звеньев после head до звена link включительно.
func j10stretch(w *world, head, link uint64) []Leaf {
	var out []Leaf
	for _, ls := range w.leaves[head:link] {
		for _, l := range ls {
			out = append(out, FromLeaf(l))
		}
	}
	return out
}

func j10promise(w *world, data []byte, recv time.Time, mmd time.Duration) Promise {
	digest := evidence.Digest(data)
	return Promise{Source: "abs-core", Seq: 2, Position: 2, Digest: digest[:], ReceivedAt: recv.UnixNano(),
		Deadline: recv.Add(mmd).UnixNano(), PublicKey: base64.RawStdEncoding.EncodeToString(w.signer.PublicKey())}
}

// j10leaf — лист записи 2: со ссылкой на запись 1 (так пишет хранилище этой
// версии) или без неё (формат v0.2.0).
func j10leaf(t *testing.T, data []byte, prevOf auditchain.Leaf, linked bool) auditchain.Leaf {
	sx, err := evidence.Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if linked {
		return EvidenceLeafLinked(sx.Header, 2, evidence.Digest(data), auditchain.LeafHash(prevOf))
	}
	return EvidenceLeaf(sx.Header, 2, evidence.Digest(data))
}

// Q-76 (ход владельца). Запись 2 (принята 10:05, срок
// 10:06) придержана за метку B (10:09), все звенья датированы задним числом.
// -promise обязан её поймать при любой версии пакета и любом формате листа:
// и то и другое выбирает владелец.
//
//	звено 1: [запуск]                      10:00, метка A над головой 1
//	звено 2: [токен A, abs-core 1]         10:02
//	звено 3: [молчит: other]               задним числом 10:05:30; метка B (10:09) над головой 3
//	звено 4: [токен B]                     задним числом 10:05:30
//	звено 5: [abs-core 2]                  задним числом 10:05:30 — придержана за B
//	звено 6: [токен C]                     метка C (10:21) над головой 5
func TestPromiseHeldBackAnyVersion(t *testing.T) {
	for _, linked := range []bool{true, false} {
		for _, v := range []int{1, 2, 3} {
			t.Run(fmt.Sprintf("linked=%v/v%d", linked, v), func(t *testing.T) {
				w := newWorld(t)
				w.now = at(10, 0, 0)
				w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
				hA, tA := w.stamp()
				w.now = at(10, 2, 0)
				r1 := rec(t, 1, at(10, 2, 0))
				w.wlink(tokenLeaf(hA, tA), r1)
				data := sealedBytes(t, 2, at(10, 5, 0), "line 2")
				w.now = at(10, 5, 30)
				w.wlink(auditchain.Leaf{UnixNano: w.now.UnixNano(), Type: auditchain.EventSilence, Scope: "other"})
				w.now = at(10, 9, 0)
				hB, tB := w.stamp()
				w.now = at(10, 5, 30)
				w.wlink(tokenLeaf(hB, tB))
				w.wlink(j10leaf(t, data, r1, linked))
				w.now = at(10, 21, 0)
				hC, tC := w.stamp()
				w.wlink(tokenLeaf(hC, tC))

				b := w.bundle(data, 5, 0, hC, tC, 2)
				b.Version = v
				if v >= 3 {
					b.Stretch = j10stretch(w, 1, 5)
				}
				r := Verify(b, w.trust())
				if !r.Valid() {
					t.Fatalf("пакет не прошёл:\n%s", r.Text())
				}
				err := CheckPromise(j10promise(w, data, at(10, 5, 0), MaxPromiseMMD), r, b, false)
				t.Logf("-promise: %v", err)
				if err == nil {
					t.Errorf("Q-76: запись, придержанная за метку B (10:09; срок 10:06), прошла -promise (лист со ссылкой: %v, версия %d)", linked, v)
				}
			})
		}
	}
}

// Q-76 (кто угодно). Честная запись 2 шла до цепи 90 с (класс
// Q-72: зависшая копия кейринга), метка B — после неё (барьер). Пакет версии
// 3 — обещание выполнено. Тот же пакет, переписанный в версию 2 или 1, не
// должен обвинять хранилище: отказ сверять — да, «нарушено» — нет.
//
//	звено 1: [запуск]                      10:00, метка A над головой 1
//	звено 2: [токен A, abs-core 1]         10:02
//	звено 3: [молчит: other]               10:06:20
//	звено 4: [abs-core 2, принята 10:05]   10:06:30
//	звено 5: [токен B]                     метка B (10:09) над головой 4
func TestPromiseRelabelledBundleRefused(t *testing.T) {
	w := newWorld(t)
	w.now = at(10, 0, 0)
	w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
	hA, tA := w.stamp()
	w.now = at(10, 2, 0)
	r1 := rec(t, 1, at(10, 2, 0))
	w.wlink(tokenLeaf(hA, tA), r1)
	data := sealedBytes(t, 2, at(10, 5, 0), "line 2")
	w.now = at(10, 6, 20)
	w.wlink(auditchain.Leaf{UnixNano: w.now.UnixNano(), Type: auditchain.EventSilence, Scope: "other"})
	w.now = at(10, 6, 30)
	w.wlink(j10leaf(t, data, r1, true))
	w.now = at(10, 9, 0)
	hB, tB := w.stamp()
	w.wlink(tokenLeaf(hB, tB))

	p := j10promise(w, data, at(10, 5, 0), MaxPromiseMMD)
	b3 := w.bundle(data, 4, 0, hB, tB, 2)
	b3.Version, b3.Stretch = 3, j10stretch(w, 1, 4)
	r3 := Verify(b3, w.trust())
	if err := CheckPromise(p, r3, b3, false); !r3.Valid() || err != nil {
		t.Fatalf("честный пакет версии 3: %s; -promise: %v", r3.Verdict(), err)
	}
	for _, v := range []int{1, 2} {
		b := b3
		b.Version, b.Stretch = v, nil
		r := Verify(b, w.trust())
		err := CheckPromise(p, r, b, false)
		t.Logf("тот же пакет с \"v\": %d — пакет %s; -promise: %v", v, r.Verdict(), err)
		if err != nil && !strings.Contains(err.Error(), "ask the store") {
			t.Errorf("Q-76: честное хранилище обвинено пакетом, у которого переписано одно неподписанное поле (версия %d)", v)
		}
	}
}

// Q-77. Запись v0.2.0 (лист без ссылки, барьера метки не было,
// promise_mmd = 10 с — v0.2.0 позволял от двух тиков) на хосте, чьи часы
// отстают от TSA на 30 с (v0.2.0 зажимал время приёма окном по якорю шириной
// 55 с — тревоги нет). Обновлённое хранилище выдаёт на неё пакет версии 3;
// обещание дано честно и не должно обвиняться.
//
//	звено 1: [запуск]                         хост 09:59:30, метка T над головой 1 (TSA 10:00:00)
//	звено 2: [токен T]                        хост 09:59:30
//	звено 3: [abs-core 2, принята 09:59:35]   хост 09:59:35 (настоящее 10:00:05)
//	звено 4: [токен T2]                       метка T2 над головой 3 (TSA 10:10:00)
func TestPromiseOldRecordMinute(t *testing.T) {
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
	w.wlink(j10leaf(t, data, auditchain.Leaf{}, false))
	w.now = at(10, 10, 0)
	h2, tok2 := w.stamp()
	w.wlink(tokenLeaf(h2, tok2))

	p := j10promise(w, data, recv, 10*time.Second)
	b := w.bundle(data, 3, 0, h2, tok2, 2)
	b.Version, b.Stretch = 3, j10stretch(w, 1, 3)
	r := Verify(b, w.trust())
	err := CheckPromise(p, r, b, false)
	t.Logf("пакет версии 3 записи v0.2.0: %s; -promise: %v", r.Verdict(), err)
	if !r.Valid() || err != nil {
		t.Errorf("Q-77: честная запись v0.2.0 (срок 10 с, часы хоста позади на 30 с) обвинена правилом меток")
	}
}
