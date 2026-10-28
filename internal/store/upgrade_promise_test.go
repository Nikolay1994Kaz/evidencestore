package store

import (
	"context"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Q-80 (заход 2 нового цикла, 28.10): класс Q-77.
//
// Q-77 отличал запись v0.2.0 по формату листа (без ссылки на прежнюю) и
// только ей прощал короткий срок v0.2.0 (promise_mmd от двух тиков, в
// демо-скриптах 10 с). Но лист записи, легшей в цепь уже после обновления,
// пишет хранилище этого выпуска — со ссылкой: догон журнала улик после
// подъёма из копии (её проход везёт журнал улик дальше подписанной головы:
// снимок цепи — раньше снимка журнала, и листья последнего тика ещё в
// памяти) или после неряшливой остановки v0.2.0. Обещание у сборщика —
// прежнее, от v0.2.0, со сроком 10 с; часы хоста позади TSA на 30 с (как в
// TestPromiseOldRecordMinute: окно по якорю это пропускает без тревоги).
// Метка T1 честно легла ДО приёма записи, а время её TSA позже времени приёма
// на ~28 с — правило меток с коротким сроком обвиняет честное хранилище. Та
// же запись, оставшаяся в цепи v0.2.0 (лист без ссылки), проходит по минуте.
//
// Обещание v0.2.0 здесь подписано ключом хранилища теми же байтами, что
// подписал бы v0.2.0 при promise_mmd = 10 с: формат обещания (домен
// evidencestore/promise/v1) и улики с v0.2.0 не менялись, а этот выпуск
// promise_mmd короче 55 с не принимает.
func TestOldPromiseRelinkedAfterRestore(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	tsaAhead := func() time.Time { return c.now().Add(30 * time.Second) }
	s.tsaLocal.Now = tsaAhead
	ctx := context.Background()

	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s)
	c.add(time.Minute)
	ingest(t, s, "abs-core", 2, 2)
	mustStamp(t, s) // T1 записи 3
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	c.add(2 * time.Second)
	res := ingest(t, s, "abs-core", 3, 3)
	cur := *res[0].Promise
	old := cur // обещание v0.2.0 с promise_mmd = 10 с
	old.Deadline = old.ReceivedAt + int64(10*time.Second)
	old.Signature = s.signer.SignMessage(proof.PromiseBytes(old))
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	// Проход копии: журнал улик уехал, цепь — нет.
	if _, err := s.ShipOnce(ctx, failingRemote{remote, "chain/"}); err == nil {
		t.Fatal("отказ копии не сработал")
	}
	s.Close()
	c.add(10 * time.Minute)
	s2, err := restoreCopy(t, cfg, s, remote, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.tsaLocal.Now = tsaAhead
	mustStampNow(t, s2)

	b, err := s2.Proof("abs-core", 3, false)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, trustOf(t, s2))
	_, linked := proof.EvidencePrev(b.Inclusion.Leaf.Chain())
	t.Logf("пакет записи 3: %s, версия %d, лист со ссылкой: %v; T1 = %s, время приёма %s",
		r.Verdict(), b.Version, linked, r.Lower.Format(time.TimeOnly), time.Unix(0, r.Header.ReceivedAt).UTC().Format(time.TimeOnly))
	if !r.Valid() {
		t.Fatalf("пакет записи 3 не прошёл:\n%s", r.Text())
	}
	if err := proof.CheckPromise(cur, r, b, false); err != nil {
		t.Fatalf("обещание этого выпуска: %v", err)
	}
	perr := proof.CheckPromise(old, r, b, false)
	t.Logf("обещание v0.2.0 (срок 10 с): %v", perr)
	if perr != nil {
		t.Errorf("Q-80: честное хранилище после подъёма из копии v0.2.0 обвинено правилом меток: %v", perr)
	}
}

// Q-80, второй путь: v0.2.0 упал (питание, OOM, SIGKILL) в тике после
// fsync записи — запись в журнале улик, лист только в памяти; поднимает
// data_dir уже этот выпуск, и догон кладёт лист записи со ссылкой.
func TestOldPromiseCaughtUpAfterCrash(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	tsaAhead := func() time.Time { return c.now().Add(30 * time.Second) }
	s.tsaLocal.Now = tsaAhead
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s)
	c.add(time.Minute)
	ingest(t, s, "abs-core", 2, 2)
	mustStamp(t, s) // T1 записи 3
	c.add(2 * time.Second)
	res := ingest(t, s, "abs-core", 3, 3) // лист в памяти, звена нет
	old := *res[0].Promise
	old.Deadline = old.ReceivedAt + int64(10*time.Second)
	old.Signature = s.signer.SignMessage(proof.PromiseBytes(old))
	crashed := copyDirs(t, cfg)

	c.add(time.Minute)
	s2 := openStore(t, crashed, c)
	s2.tsaLocal.Now = tsaAhead
	mustStampNow(t, s2)
	b, err := s2.Proof("abs-core", 3, false)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, trustOf(t, s2))
	_, linked := proof.EvidencePrev(b.Inclusion.Leaf.Chain())
	perr := proof.CheckPromise(old, r, b, false)
	t.Logf("пакет записи 3: %s, лист со ссылкой: %v; обещание v0.2.0 (срок 10 с): %v", r.Verdict(), linked, perr)
	if !r.Valid() || perr != nil {
		t.Errorf("Q-80: честное хранилище после падения v0.2.0 обвинено правилом меток: %v", perr)
	}
}
