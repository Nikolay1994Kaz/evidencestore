package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Пакет по сделке (DECISIONS, п. 42): квитанции действия a-1 называют
// транзакцию 754 источника базы, и esverify сводит пакет квитанций с пакетом
// транзакции: оба проходят, связь — по открытой квитанции. Пакет чужой
// транзакции, пропавший пакет, пакет не того вида — отказ.
func TestDealBundle(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	w := openWorld(t, []config.Source{
		{Name: "agent-mcp", ContentType: config.ReceiptContentType, GatewayKey: pub, SubjectField: config.ReceiptSubjectField},
		{Name: "pg-agent", ContentType: "pg/before-images-v1", SubjectField: "xid"},
	})
	gw, _ := gateway.NewSigner(key, "esmcp", nil)
	receipt := func(action, step string, refs ...gateway.Ref) string {
		line, err := gw.Sign(gateway.Draft{Time: time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC), Action: action, Step: step, Refs: refs, Body: json.RawMessage(`{"agent":"bot"}`)})
		if err != nil {
			t.Fatal(err)
		}
		return string(line)
	}
	w.line(t, "agent-mcp", 1, receipt("a-0", "intent", gateway.Ref{Source: "pg-agent", Subject: "700"}))
	w.stamp(t)
	w.advance(5 * time.Minute)
	w.line(t, "agent-mcp", 2, receipt("a-1", "intent", gateway.Ref{Source: "pg-agent", Subject: "754"}))
	w.line(t, "pg-agent", 1, `{"xid":754,"part":1,"last":true,"gz":""}`)
	w.line(t, "pg-agent", 2, `{"xid":755,"part":1,"last":true,"gz":""}`)
	w.line(t, "agent-mcp", 3, receipt("a-1", "outcome"))
	w.advance(5 * time.Minute)
	w.closeUp(t)
	bundle := func(source, subject string) string {
		b, err := w.s.ProofSubject(source, subject, w.from, w.to, 0)
		if err != nil {
			t.Fatal(err)
		}
		return w.file(t, source+"-"+subject+".json", b)
	}
	receipts, tx, other := bundle("agent-mcp", "a-1"), bundle("pg-agent", "754"), bundle("pg-agent", "755")

	bodies := filepath.Join(w.dir, "bodies")
	code, out, errOut := w.run(t, receipts, "-linked", tx, "-gateway-key", pub, "-bodies", bodies)
	if code != exitValid || !strings.HasPrefix(out, "VERIFIED\n\nDeal: action \"a-1\" of gateway \"esmcp\", 2 receipts open\n") ||
		!strings.Contains(out, `named by receipts [2]: "pg-agent" "754" — linked bundle 1: 1 records, 1 open`) ||
		!strings.Contains(out, "2 signatures checked with your gateway key") || !strings.Contains(out, "=== linked bundle 1 ("+tx+") ===") {
		t.Fatalf("код %d:\n%s\n%s", code, out, errOut)
	}
	files, _ := os.ReadDir(bodies)
	var names []string
	for _, f := range files {
		names = append(names, f.Name())
	}
	if strings.Join(names, " ") != "agent-mcp-2 agent-mcp-3 pg-agent-1" {
		t.Fatalf("файлы %v", names)
	}
	code, out, _ = w.run(t, receipts, "-linked", tx, "-json")
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); code != exitValid || err != nil || rep["kind"] != "deal" || rep["action"] != "a-1" ||
		rep["gateway_key_checked"] != false || len(rep["bundles"].([]any)) != 2 || len(rep["links"].([]any)) != 1 {
		t.Fatalf("код %d, %v:\n%s", code, err, out)
	}

	for name, c := range map[string]struct {
		args []string
		code int
		want string
	}{
		"another transaction":             {[]string{"-linked", other}, exitInvalid, `linked bundle 1 (pg-agent "755") is named by no receipt of the action`},
		"no linked bundle of it":          {[]string{"-linked", other}, exitInvalid, `names pg-agent "754", and no linked bundle is of it`},
		"the deal starts at the receipts": {[]string{"-linked", receipts}, exitInvalid, "holds no gateway receipts"},
		"a missing file":                  {[]string{"-linked", filepath.Join(w.dir, "nope.json")}, exitUsage, "-linked"},
		"not a source bundle":             {[]string{"-linked", w.file(t, "single.json", []byte(`{"v":1}`))}, exitUsage, "a bundle by subject of one source"},
	} {
		proofFile := receipts
		if name == "the deal starts at the receipts" {
			proofFile = tx
		}
		code, out, errOut := w.run(t, proofFile, c.args...)
		if code != c.code || !strings.Contains(out+errOut, c.want) {
			t.Errorf("%s: код %d:\n%s\n%s", name, code, out, errOut)
		}
	}
	// С -linked пакет одной улики — неверный вызов.
	single := w.file(t, "one.json", []byte(`{"v":3,"evidence":""}`))
	if code, _, errOut := w.run(t, single, "-linked", tx); code != exitUsage || !strings.Contains(errOut, "-linked are for a bundle over a window") {
		t.Fatalf("код %d: %s", code, errOut)
	}
}

// Сделка через границу месяцев (R1-1): действие a-1 идёт 23:55 31.10 → 00:05
// 01.11 — намерение и часть 1 транзакции 754 в октябре, часть 2 и исход в
// ноябре. Кто держит пакеты до проверяющего, заменяет в обоих метку ноября
// выдуманной и снимает ключи записей ноября: подписи на метках нет (P-75), и
// открытые записи октября оставались «всеми записями» — сделка проходила со
// спрятанными исходом и частью транзакции. Теперь месяц окна, где не открыто
// ни одно тело субъекта, — отказ.
func TestDealRefusesAMonthWithoutAnOpenBody(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	w := openWorldAt(t, []config.Source{
		{Name: "agent-mcp", ContentType: config.ReceiptContentType, GatewayKey: pub, SubjectField: config.ReceiptSubjectField},
		{Name: "pg-agent", ContentType: "pg/before-images-v1", SubjectField: "xid"},
	}, time.Date(2026, 10, 31, 23, 50, 0, 0, time.UTC))
	gw, _ := gateway.NewSigner(key, "esmcp", nil)
	receipt := func(action, step string, refs ...gateway.Ref) string {
		line, err := gw.Sign(gateway.Draft{Time: time.Date(2026, 10, 31, 23, 55, 0, 0, time.UTC), Action: action, Step: step, Refs: refs,
			Body: json.RawMessage(`{"agent":"bot","outcome":"` + step + `"}`)})
		if err != nil {
			t.Fatal(err)
		}
		return string(line)
	}
	w.line(t, "agent-mcp", 1, receipt("a-0", "intent", gateway.Ref{Source: "pg-agent", Subject: "700"}))
	w.stamp(t)
	w.advance(5 * time.Minute) // 23:55, октябрь
	w.line(t, "agent-mcp", 2, receipt("a-1", "intent", gateway.Ref{Source: "pg-agent", Subject: "754"}))
	w.line(t, "pg-agent", 1, `{"xid":754,"part":1,"last":false,"gz":""}`)
	w.advance(10 * time.Minute) // 00:05, ноябрь
	w.line(t, "pg-agent", 2, `{"xid":754,"part":2,"last":true,"gz":""}`)
	w.line(t, "agent-mcp", 3, receipt("a-1", "outcome"))
	w.advance(5 * time.Minute)
	w.closeUp(t)
	from, to := time.Date(2026, 10, 31, 23, 54, 0, 0, time.UTC), time.Date(2026, 11, 1, 0, 6, 0, 0, time.UTC)
	receipts, err := w.s.ProofSubject("agent-mcp", "a-1", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := w.s.ProofSubject("pg-agent", "754", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := w.run(t, w.file(t, "receipts.json", receipts), "-linked", w.file(t, "tx.json", tx), "-gateway-key", pub)
	if code != exitValid || !strings.Contains(out, "2 receipts open") || !strings.Contains(out, "linked bundle 1: 2 records, 2 open") {
		t.Fatalf("the honest deal across midnight: exit %d\n%s\n%s", code, out, errOut)
	}
	hide := func(b proof.SourceBundle, scope string) proof.SourceBundle {
		data, _ := json.Marshal(b)
		var f proof.SourceBundle
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		found := false
		for i, l := range f.Subject.Labels {
			if l.Scope == scope {
				f.Subject.Labels[i].Tag, found = []byte("0123456789abcdef"), true
			}
		}
		if !found {
			t.Fatalf("no label of %s in the bundle: %+v", scope, f.Subject.Labels)
		}
		for i := range f.Records {
			if sealed, err := evidence.Unmarshal(f.Records[i].Evidence); len(f.Records[i].Evidence) > 0 && err == nil && sealed.Scope() == scope {
				f.Records[i].DEK = nil
			}
		}
		return f
	}
	for _, c := range []struct {
		name         string
		receipts, tx proof.SourceBundle
		why          string
	}{
		{"the outcome receipt hidden", hide(receipts, "agent-mcp/2026-11"), tx, `the receipts of action "a-1": no body of it is open in "agent-mcp/2026-11"`},
		{"part 2 of the transaction hidden", receipts, hide(tx, "pg-agent/2026-11"), `pg-agent "754" (linked bundle 1): no body of it is open in "pg-agent/2026-11"`},
	} {
		bodies := filepath.Join(w.dir, "bodies-"+strings.ReplaceAll(c.name, " ", "-"))
		code, out, errOut := w.run(t, w.file(t, "r.json", c.receipts), "-linked", w.file(t, "t.json", c.tx), "-gateway-key", pub, "-bodies", bodies)
		if code == exitValid || !strings.Contains(out, c.why) || !strings.Contains(out, "ask for a window inside the months where the action has records") {
			t.Errorf("%s: exit %d, want a refusal naming %q\n%s\n%s", c.name, code, c.why, out, errOut)
		}
		if files, _ := os.ReadDir(bodies); len(files) != 0 {
			t.Errorf("%s: the bodies of a deal that does not verify are written: %d files", c.name, len(files))
		}
	}
}

// Шлюз сменил ключ (DECISIONS, п. 47): проверяющий называет оба ключа —
// каждым своим -gateway-key или файлом со списком и сроками, как gateway_keys
// источника, — и срок его ключа сверяется со временем приёма из пакета.
func TestGatewayKeysOfTheAuditor(t *testing.T) {
	oldKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	newKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	oldPub, newPub := hex.EncodeToString(oldKey.Public().(ed25519.PublicKey)), hex.EncodeToString(newKey.Public().(ed25519.PublicKey))
	w := openWorld(t, []config.Source{{Name: "agent-mcp", ContentType: config.ReceiptContentType, SubjectField: config.ReceiptSubjectField,
		GatewayKeys: []gateway.KeyEntry{{Key: oldPub, NotAfter: "2026-10-26T10:05:30Z"}, {Key: newPub}}}})
	at := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	sign := func(s *gateway.Signer, step string) (string, gateway.Receipt) {
		line, err := s.Sign(gateway.Draft{Time: at, Action: "a-1", Step: step})
		if err != nil {
			t.Fatal(err)
		}
		r, _ := gateway.ParseReceipt(line)
		return string(line), r
	}
	was, _ := gateway.NewSigner(oldKey, "esmcp", nil)
	now, _ := gateway.NewSigner(newKey, "esmcp", nil)
	first, _ := sign(was, "start")
	w.line(t, "agent-mcp", 1, first)
	w.stamp(t)
	w.advance(5 * time.Minute) // 10:05: прежний ключ ещё говорит за шлюз
	intent, last := sign(was, "intent")
	w.line(t, "agent-mcp", 2, intent)
	if err := now.After(last.Seq, last.Hash); err != nil {
		t.Fatal(err)
	}
	outcome, _ := sign(now, "outcome")
	w.line(t, "agent-mcp", 3, outcome)
	w.advance(5 * time.Minute)
	w.closeUp(t)
	b, err := w.s.ProofSubject("agent-mcp", "a-1", w.from, w.to, 0)
	if err != nil {
		t.Fatal(err)
	}
	bundle := w.file(t, "a-1.json", b)

	code, out, errOut := w.run(t, bundle, "-gateway-key", oldPub, "-gateway-key", newPub)
	if code != exitValid || !strings.Contains(out, "2 signatures checked with your gateway key") {
		t.Fatalf("оба ключа: код %d\n%s%s", code, out, errOut)
	}
	// Тот же список файлом, со сроками: квитанции приняты в 10:05.
	list := func(name, entries string) string { return w.file(t, name, []byte("["+entries+"]")) }
	fits := list("keys.json", `{"key":"`+oldPub+`","not_after":"2026-10-26T10:05:30Z"},{"key":"`+newPub+`","not_before":"2026-10-26T10:00:00Z"}`)
	if code, out, errOut := w.run(t, bundle, "-gateway-key", fits); code != exitValid || !strings.Contains(out, "2 signatures checked with your gateway key") {
		t.Fatalf("список со сроками: код %d\n%s%s", code, out, errOut)
	}
	// Один ключ из двух — чья-то квитанция не проверена.
	for _, one := range []string{oldPub, newPub} {
		if code, out, _ := w.run(t, bundle, "-gateway-key", one); code != exitInvalid || !strings.Contains(out, "not among the gateway keys") {
			t.Fatalf("один ключ из двух: код %d\n%s", code, out)
		}
	}
	// У проверяющего прежний ключ отозван с 10:02 — раньше, чем квитанция
	// принята: пакет не проходит, хотя хранилище назвало её целой.
	early := list("early.json", `{"key":"`+oldPub+`","not_after":"2026-10-26T10:02:00Z"},"`+newPub+`"`)
	if code, out, _ := w.run(t, bundle, "-gateway-key", early); code != exitInvalid || !strings.Contains(out, "no longer speaks for the gateway") {
		t.Fatalf("ключ, отозванный проверяющим: код %d\n%s", code, out)
	}
	// Настройки, которые не разобрать, — отказ до проверки, а не ключ без срока.
	for name, args := range map[string][]string{
		"ключ дважды":            {"-gateway-key", oldPub, "-gateway-key", oldPub},
		"опечатка в сроке":       {"-gateway-key", list("typo.json", `{"key":"`+oldPub+`","not_afer":"2026-10-26T10:02:00Z"}`)},
		"срок не временем":       {"-gateway-key", list("time.json", `{"key":"`+oldPub+`","not_after":"soon"}`)},
		"пустой список":          {"-gateway-key", list("empty.json", ``)},
		"не ключ и не файл":      {"-gateway-key", "no-such-file"},
		"файл с коротким ключом": {"-gateway-key", w.file(t, "short.pub", []byte("abcd\n"))},
	} {
		if code, _, errOut := w.run(t, bundle, args...); code != exitUsage {
			t.Errorf("%s: код %d, %s", name, code, errOut)
		}
	}
}
