package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Общая квитанция шлюза (DECISIONS, п. 43) на настоящем хранилище: подпись и
// сцепка при приёме, вердикт в цепи, пакет по записи и по одному действию.

func receiptGateway(t *testing.T, seed byte) (ed25519.PrivateKey, string) {
	t.Helper()
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return k, hex.EncodeToString(k.Public().(ed25519.PublicKey))
}

func withReceipts(pub string) func(*config.Config) {
	return func(c *config.Config) {
		c.Sources = append(c.Sources, config.Source{Name: "shop", ContentType: config.ReceiptContentType,
			GatewayKey: pub, SubjectField: config.ReceiptSubjectField})
	}
}

func sign(t *testing.T, s *gateway.Signer, action, step string) []byte {
	t.Helper()
	line, err := s.Sign(gateway.Draft{Time: time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC), Action: action, Step: step,
		Body: json.RawMessage(`{"note":"` + action + " " + step + `"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func ingestShop(t *testing.T, s *Store, seq uint64, line []byte) {
	t.Helper()
	if _, err := s.Ingest("shop", []Incoming{{Seq: seq, Body: line}}); err != nil {
		t.Fatal(err)
	}
}

func receiptTrust(t *testing.T, s *Store, pub string) proof.Trust {
	t.Helper()
	tr := trustOf(t, s)
	k, err := gateway.ParseKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	tr.GatewayKey = k
	return tr
}

func TestReceiptContentTypesAgree(t *testing.T) {
	if config.ReceiptContentType != gateway.ReceiptContentType || config.GatewayContentType != gateway.ContentType {
		t.Fatal("config and gateway name the content types differently")
	}
	for _, ct := range []string{config.ReceiptContentType, config.GatewayContentType, "syslog", "purchase-events"} {
		if config.VerifiedContentType(ct) != gateway.Verified(ct) {
			t.Fatalf("%s: config and gateway disagree on whether it is checked at intake", ct)
		}
	}
}

// ⭐ Квитанция через хранилище: вердикт рядом в цепи, пакет по записи
// проверяется офлайн с ключом шлюза — тело то самое, разбирается без
// хранилища, подписано шлюзом.
func TestReceiptProof(t *testing.T) {
	key, pub := receiptGateway(t, 1)
	c := newClock()
	s := openStore(t, testConfig(t, withReceipts(pub)), c)
	gw, _ := gateway.NewSigner(key, "shop-gw", nil)
	for i, step := range []string{"mandate", "cart", "payment"} {
		ingestShop(t, s, uint64(i+1), sign(t, gw, "p-1", step))
	}
	mustStamp(t, s)

	b, err := s.Proof("shop", 2, true)
	if err != nil {
		t.Fatal(err)
	}
	tr := receiptTrust(t, s, pub)
	r := proof.Verify(b, tr)
	if !r.Valid() || !r.Receipt || !r.ReceiptSigned || !r.GatewayKeyChecked || r.Gateway == nil || r.Gateway.Seq != 2 || r.Gateway.Link != gateway.LinkOK {
		t.Fatalf("пакет:\n%s", r.Text())
	}
	for _, name := range []string{
		"the body is that very gateway receipt (hash recomputed)",
		"the gateway receipt is well-formed (parsed offline)",
		"the gateway receipt is signed with the pinned gateway key",
	} {
		if !hasCheck(r, name) {
			t.Fatalf("нет пройденной проверки %q:\n%s", name, r.Text())
		}
	}
	if s.tailKind("shop") != gateway.ReceiptContentType {
		t.Fatalf("вид источника в хвостах %q", s.tailKind("shop"))
	}

	_, other := receiptGateway(t, 2)
	if proof.Verify(b, receiptTrust(t, s, other)).Valid() {
		t.Fatal("квитанция сошлась с чужим ключом шлюза")
	}
	// Без ключа проверяющего подпись проверило только хранилище: это предел,
	// и он назван.
	tr.GatewayKey = nil
	r = proof.Verify(b, tr)
	if !r.Valid() || !strings.Contains(strings.Join(r.Notes(), "\n"), "esverify -gateway-key") {
		t.Fatalf("без ключа шлюза:\n%s", r.Text())
	}
	// Без тела подпись не проверить, и отчёт говорит об этом.
	nb, err := s.Proof("shop", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.Verify(nb, receiptTrust(t, s, pub)); !r.Valid() || !strings.Contains(strings.Join(r.Notes(), "\n"), "the body is not opened") {
		t.Fatalf("без тела:\n%s", r.Text())
	}
	// Часть gateway не вырезать: квитанция без вердикта не проходит.
	b.Gateway = nil
	if proof.Verify(b, receiptTrust(t, s, pub)).Valid() {
		t.Fatal("пакет по квитанции без вердикта прошёл")
	}
}

// Квитанция, подписанная не ключом шлюза, принимается как пришла, а вердикт
// и пакет называют подпись неверной. Выпавшая квитанция — поломка сцепки у
// следующей.
func TestReceiptForgedAndDropped(t *testing.T) {
	key, pub := receiptGateway(t, 3)
	forgerKey, _ := receiptGateway(t, 4)
	c := newClock()
	cfg := testConfig(t, withReceipts(pub))
	s := openStore(t, cfg, c)
	gw, _ := gateway.NewSigner(key, "shop-gw", nil)
	forger, _ := gateway.NewSigner(forgerKey, "shop-gw", nil)
	ingestShop(t, s, 1, sign(t, gw, "p-1", "mandate"))
	ingestShop(t, s, 2, sign(t, forger, "p-1", "cart"))
	sign(t, gw, "p-1", "cart") // seq 2 шлюза в хранилище не пришла
	ingestShop(t, s, 3, sign(t, gw, "p-1", "payment"))
	mustStamp(t, s)

	if got := s.sources["shop"].gwProblems.Load(); got != 2 {
		t.Fatalf("поломок %d, ожидали 2", got)
	}
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	leaves := leavesOf(t, cfg, auditchain.EventGateway)
	if len(leaves) != 3 {
		t.Fatalf("вердиктов %d", len(leaves))
	}
	var vs []gateway.Verdict
	for _, l := range leaves {
		_, v, err := proof.ParseGatewayLeaf(l)
		if err != nil {
			t.Fatal(err)
		}
		vs = append(vs, v)
	}
	if !vs[0].Clean() || vs[1].Signature != gateway.SigInvalid || vs[1].Clean() || vs[2].Link != gateway.LinkBroken || vs[2].Clean() {
		t.Fatalf("вердикты %+v", vs)
	}
	for seq := uint64(2); seq <= 3; seq++ {
		b, err := s.Proof("shop", seq, true)
		if err != nil {
			t.Fatal(err)
		}
		if r := proof.Verify(b, receiptTrust(t, s, pub)); r.Valid() {
			t.Fatalf("запись %d прошла:\n%s", seq, r.Text())
		}
	}
}

// receiptStore — источник shop, один шлюз и разные покупки, по часам теста:
//
//	10:00 квитанция 1 (p-1), метка A
//	10:02 квитанция 2 (p-2): на участке, вне окна
//	10:05 квитанции 3 (p-1), 4 (p-2), 5 (p-1): окно 10:04–10:06
//	10:08 квитанция 6 (p-1): на участке, вне окна
//	10:10 метка B, сразу за ней B′
func receiptStore(t *testing.T, pub string, key ed25519.PrivateKey, lie func(*Store)) *Store {
	t.Helper()
	c := newClock()
	s := openStore(t, testConfig(t, withReceipts(pub)), c)
	if lie != nil {
		lie(s)
	}
	gw, _ := gateway.NewSigner(key, "shop-gw", nil)
	ingestShop(t, s, 1, sign(t, gw, "p-1", "mandate"))
	mustStamp(t, s)
	c.add(2 * time.Minute)
	ingestShop(t, s, 2, sign(t, gw, "p-2", "mandate"))
	c.add(3 * time.Minute)
	ingestShop(t, s, 3, sign(t, gw, "p-1", "cart"))
	ingestShop(t, s, 4, sign(t, gw, "p-2", "cart"))
	ingestShop(t, s, 5, sign(t, gw, "p-1", "payment"))
	c.add(3 * time.Minute)
	ingestShop(t, s, 6, sign(t, gw, "p-1", "delivery"))
	c.add(2 * time.Minute)
	mustStamp(t, s)
	mustStampNow(t, s)
	return s
}

// ⭐ Пакет по одной покупке: открыты её квитанции и только они, каждая
// проверена ключом шлюза, а сцепка всех квитанций окна, и чужих закрытых,
// проверена по вердиктам: закрытую чужую квитанцию называет prev следующей.
func TestReceiptSubjectBundle(t *testing.T) {
	key, pub := receiptGateway(t, 5)
	s := receiptStore(t, pub, key, nil)
	from, to := clockAt(10, 4, 0), clockAt(10, 6, 0)
	b, err := s.ProofSubject("shop", "p-1", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), receiptTrust(t, s, pub), time.Time{}, time.Time{})
	if !r.Valid() {
		t.Fatalf("честный пакет:\n%s", r.Text())
	}
	if !slices.Equal(bodySeqs(r.Bodies), []uint64{3, 5}) || !r.Receipts || r.ReceiptsOpened != 2 || r.ReceiptsSigned != 2 || r.ReceiptLinks < 3 {
		t.Fatalf("тела %v, квитанций открыто %d, подписей %d, сцепок %d:\n%s", bodySeqs(r.Bodies), r.ReceiptsOpened, r.ReceiptsSigned, r.ReceiptLinks, r.Text())
	}
	for _, body := range r.Bodies {
		if rc, err := gateway.ParseReceipt(body.Body); err != nil || rc.Action != "p-1" {
			t.Fatalf("открыта чужая квитанция %d: %+v, %v", body.Seq, rc, err)
		}
	}
	if !strings.Contains(r.Text(), "named by the signed prev of the next") {
		t.Fatalf("в отчёте нет заметки о квитанциях:\n%s", r.Text())
	}
	_, other := receiptGateway(t, 6)
	if r := proof.VerifySource(sourceRoundTrip(t, b), receiptTrust(t, s, other), time.Time{}, time.Time{}); r.Valid() {
		t.Fatalf("пакет сошёлся с чужим ключом шлюза:\n%s", r.Text())
	}
	// Без ключа проверяющего — проходит, и отчёт просит ключ.
	if r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{}); !r.Valid() || r.ReceiptsSigned != 0 ||
		!strings.Contains(r.Text(), "esverify -gateway-key") {
		t.Fatalf("без ключа шлюза:\n%s", r.Text())
	}
	// Пакет по источнику без ключей записей: тел нет, сцепка по вердиктам — та же.
	src, err := s.ProofSource("shop", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(sourceRoundTrip(t, src), receiptTrust(t, s, pub), time.Time{}, time.Time{}); !r.Valid() || r.ReceiptLinks < 3 || r.ReceiptsOpened != 0 {
		t.Fatalf("пакет по источнику:\n%s", r.Text())
	}
}

// Строка с чужой подписью под меткой покупки: хранилище её принимает и
// называет поломанной, пакет по покупке её не открывает и называет, а
// следующая настоящая квитанция цела — подделка в цепочку шлюза не входит.
func TestReceiptForgedInSubjectBundle(t *testing.T) {
	key, pub := receiptGateway(t, 9)
	forgerKey, _ := receiptGateway(t, 10)
	c := newClock()
	s := openStore(t, testConfig(t, withReceipts(pub)), c)
	gw, _ := gateway.NewSigner(key, "shop-gw", nil)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // 10:00
	c.add(time.Minute)
	ingestShop(t, s, 1, sign(t, gw, "p-1", "mandate"))
	second := sign(t, gw, "p-2", "mandate")
	ingestShop(t, s, 2, second)
	prev, _ := gateway.ParseReceipt(second)
	ingestShop(t, s, 3, forgeAfter(t, forgerKey, prev, "p-1", "cancel"))
	ingestShop(t, s, 4, sign(t, gw, "p-1", "cart"))
	c.add(5 * time.Minute)
	mustStamp(t, s) // 10:06
	mustStampNow(t, s)
	b, err := s.ProofSubject("shop", "p-1", clockAt(10, 0, 30), clockAt(10, 3, 30), 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), receiptTrust(t, s, pub), time.Time{}, time.Time{})
	if !r.Valid() || !slices.Equal(r.GatewayBroken, []uint64{3}) || r.Withheld() != 1 || !slices.Equal(bodySeqs(r.Bodies), []uint64{1, 4}) || r.ReceiptsSigned != 2 {
		t.Fatalf("поломано %v, не вскрыто %d, тела %v, подписей %d:\n%s", r.GatewayBroken, r.Withheld(), bodySeqs(r.Bodies), r.ReceiptsSigned, r.Text())
	}
	if r.SubjectRecords != 2 || r.SubjectOpened != 2 || r.SubjectForged != 1 || !strings.Contains(r.Text(), "gateway receipts 3 were found broken by the store at intake") ||
		!strings.Contains(r.Text(), `records 3 lie under the label of "p-1", and the store found at intake that they are not signed with the gateway key`) {
		t.Fatalf("поломка не названа:\n%s", r.Text())
	}
	// Подделка под меткой действия — не квитанция шлюза: сделку по p-1 она не
	// держит (R1-6). Раньше «2 of its 3 records in the window are open» —
	// и действие, обе квитанции которого открыты и подписаны ключом шлюза,
	// доказать было нельзя: номер действия видно в файле, строку дописать
	// может любой, кто пишет в файл.
	if d := proof.LinkDeal(r, nil); !d.Valid() {
		t.Fatalf("сделка по p-1 не сводится из-за строки с чужой подписью:\n%s", d.Text())
	}
}

// forgeAfter — квитанция «следом за prev» того же шлюза, подписанная чужим
// ключом: строка собрана так, как её собрал бы сам шлюз.
func forgeAfter(t *testing.T, key ed25519.PrivateKey, prev gateway.Receipt, action, step string) []byte {
	t.Helper()
	b := `{"v":1,"gateway":"` + prev.Gateway + `","seq":` + strconv.FormatUint(prev.Seq+1, 10) + `,"prev":"` + prev.Hash +
		`","time":"2026-09-25T10:01:00Z","action":"` + action + `","step":"` + step + `"}`
	sig := ed25519.Sign(key, append([]byte("evidencestore/receipt/v1\n"), b...))
	return []byte(b[:len(b)-1] + `,"sig":"` + hex.EncodeToString(sig) + `"}`)
}

// liarChecker — хранилище, которое называет каждую квитанцию сцепленной.
type liarChecker struct{ gateway.Checker }

func (l liarChecker) Check(line []byte) gateway.Verdict {
	v := l.Checker.Check(line)
	v.Link, v.Problem = gateway.LinkOK, ""
	return v
}

// Хранилище солгало в вердикте («linked» при выпавшей квитанции): хэши
// вердиктов в пакете этого не подтверждают, и пакет не проходит, даже без
// единого открытого тела.
func TestReceiptVerdictLieIsSeen(t *testing.T) {
	key, pub := receiptGateway(t, 7)
	c := newClock()
	s := openStore(t, testConfig(t, withReceipts(pub)), c)
	s.sources["shop"].gw = liarChecker{s.sources["shop"].gw}
	gw, _ := gateway.NewSigner(key, "shop-gw", nil)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // 10:00
	c.add(time.Minute)
	ingestShop(t, s, 1, sign(t, gw, "p-1", "mandate"))
	sign(t, gw, "p-2", "mandate") // не дошла
	ingestShop(t, s, 2, sign(t, gw, "p-1", "cart"))
	c.add(5 * time.Minute)
	mustStamp(t, s) // 10:06
	mustStampNow(t, s)
	b, err := s.ProofSource("shop", clockAt(10, 0, 30), clockAt(10, 3, 30), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), receiptTrust(t, s, pub), time.Time{}, time.Time{})
	if r.Valid() || !strings.Contains(r.Text(), `is "broken" after its seq 1 in the bundle, and the store's verdict calls it "linked"`) {
		t.Fatalf("ложь хранилища в вердикте прошла:\n%s", r.Text())
	}
}

// hashLiar — хранилище, которое пишет в вердикт квитанции действия p-lie
// чужой хэш: тело и вердикт расходятся.
type hashLiar struct{ gateway.Checker }

func (l hashLiar) Check(line []byte) gateway.Verdict {
	v := l.Checker.Check(line)
	if r, _ := gateway.ParseReceipt(line); r.Action == "p-lie" {
		v.Hash = strings.Repeat("0", 64)
	}
	return v
}

// Вердикт называет не ту квитанцию, что в теле: ни пакет по записи, ни пакет
// по действию не проходят. Квитанция — последняя в цепи: сцепка по вердиктам
// её чужой хэш не видит, видит только сверка тела.
func TestReceiptBodyAgainstVerdict(t *testing.T) {
	key, pub := receiptGateway(t, 11)
	c := newClock()
	s := openStore(t, testConfig(t, withReceipts(pub)), c)
	s.sources["shop"].gw = hashLiar{s.sources["shop"].gw}
	gw, _ := gateway.NewSigner(key, "shop-gw", nil)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // 10:00
	c.add(time.Minute)
	ingestShop(t, s, 1, sign(t, gw, "p-1", "mandate"))
	ingestShop(t, s, 2, sign(t, gw, "p-lie", "cart"))
	c.add(5 * time.Minute)
	mustStamp(t, s) // 10:06
	mustStampNow(t, s)
	b, err := s.Proof("shop", 2, true)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.Verify(b, receiptTrust(t, s, pub)); r.Valid() || !strings.Contains(r.Text(), "body hash") {
		t.Fatalf("пакет по записи с чужим хэшем в вердикте прошёл:\n%s", r.Text())
	}
	sb, err := s.ProofSubject("shop", "p-lie", clockAt(10, 0, 30), clockAt(10, 3, 30), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(sourceRoundTrip(t, sb), receiptTrust(t, s, pub), time.Time{}, time.Time{}); r.Valid() || !strings.Contains(r.Text(), "the body is not the receipt the verdict names") {
		t.Fatalf("пакет по действию с чужим хэшем в вердикте прошёл:\n%s", r.Text())
	}
}

// Падение между журналом улик и вердиктом: при подъёме вердикты квитанций
// досчитываются по телам, сцепка продолжается с того же места.
func TestReceiptVerdictCatchUp(t *testing.T) {
	key, pub := receiptGateway(t, 8)
	c := newClock()
	cfg := testConfig(t, withReceipts(pub))
	s := openStore(t, cfg, c)
	gw, _ := gateway.NewSigner(key, "shop-gw", nil)
	var lines [][]byte
	for i := range 9 {
		lines = append(lines, sign(t, gw, "p-"+string(rune('1'+i%3)), "step"))
	}
	for i, l := range lines[:3] {
		ingestShop(t, s, uint64(i+1), l)
	}
	s.flush()
	for i, l := range lines[3:6] {
		ingestShop(t, s, uint64(i+4), l) // вердикты ещё в памяти
	}
	crashed := copyDirs(t, cfg)
	s2 := openStore(t, crashed, c)
	for i, l := range lines[6:] {
		ingestShop(t, s2, uint64(i+7), l)
	}
	s2.flush()
	got := leavesOf(t, crashed, auditchain.EventGateway)
	if len(got) != len(lines) {
		t.Fatalf("вердиктов %d, квитанций %d", len(got), len(lines))
	}
	for i, l := range got {
		_, v, err := proof.ParseGatewayLeaf(l)
		want := gateway.LinkOK
		if i == 0 {
			want = gateway.LinkGenesis
		}
		if err != nil || !v.Clean() || v.Seq != uint64(i+1) || v.Link != want || v.Signature != gateway.SigValid {
			t.Fatalf("вердикт %d: %+v, %v", i, v, err)
		}
	}
}
