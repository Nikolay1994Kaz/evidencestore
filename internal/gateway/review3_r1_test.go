package gateway

// Третий заход проверки (R1, 24.11): находки по шлюзу. Каждый тест здесь
// ПАДАЕТ на 1f9a0f2 — значит, уязвимость есть.
// go test ./internal/gateway -run R1Rev8 -count=1 -v

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// R1-4. Голову P-357 защитили от ссылок (O_NOFOLLOW, только обычный файл), а
// сам файл квитанций шлюз открывает по ссылке: os.OpenFile(path,
// O_RDWR|O_CREATE|O_APPEND). Противник 3 (пишет в каталог квитанций, ключа и
// головы не читает) кладёт на место receipts.jsonl ссылку туда, куда шлюз
// писать может, а сборщик этого не видит. Здесь — на файл головы шлюза
// (путь в Docker постоянный: /state/mcp-head/esmcp.head; по умолчанию —
// <ключ>.head-<hex от пути и имени>): квитанция ложится в inode головы,
// writeHead тут же заменяет голову переименованием — квитанции нет нигде.
// AppendHead при этом возвращает nil: шлюз считает намерение записанным с
// fsync и пускает SQL агента. Сборщик по ссылке читает голову (JSON без
// перевода строки — обрывок, ни строки, ни тревоги); в Docker у контейнера
// сборщика каталога mcp-head нет — ссылка висит, ENOENT, «шлюз ещё не
// писал». Ссылка на /tmp контейнера esmcp — то же без знания пути головы.
// Каждое действие агента — отпечатком, без тревоги (require_gateway в
// Docker не задан), исходы (escaped, refused) — без тревог; счёт пределов
// MCP-сервера (ledger) читает тот же путь и не видит ни одного действия.
func TestR1Rev8ReceiptsPathSymlinkSwallowsReceipts(t *testing.T) {
	key := receiptKey(t, 77)
	dir := t.TempDir() // каталог квитанций: пишет и противник 3
	path := filepath.Join(dir, "receipts.jsonl")
	head := headOf(t, path) // рядом с ключом, в другом каталоге
	mustAppendHead(t, path, head, key, "a-1")
	before := len(receiptLines(t, path))

	// Противник 3: на месте файла квитанций — ссылка на голову шлюза.
	os.Rename(path, path+".1")
	if err := os.Symlink(head, path); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"a-2", "a-3", "a-4"} {
		if _, err := AppendHead(path, head, key, "esmcp", Draft{Time: at, Action: a, Step: "intent", Refs: []Ref{{Source: "pg", Subject: "754"}}}); err != nil {
			t.Logf("AppendHead refused through the link: %v", err)
			return
		}
	}
	// Что видит читатель файла квитанций (сборщик, его файловый вход, счёт
	// пределов MCP-сервера) по пути из настроек.
	data, _ := os.ReadFile(path)
	n := 0
	for _, l := range bytes.Split(data, []byte("\n")) {
		if _, err := ParseReceipt(l); err == nil {
			n++
		}
	}
	h, ok, err := readHead(head)
	t.Logf("before the link: %d receipts; through the link: %d receipts; head ok=%v seq=%d err=%v; %q", before, n, ok, h.Seq, err, data)
	t.Errorf("AppendHead wrote 3 receipts through a link planted at the receipts path and reported success; a reader of the path sees %d of them", n)
}

// R1-4б. Ссылка на файл вне каталога квитанций, который читатель не видит
// (в Docker — /tmp контейнера esmcp, `docker compose run --rm` его
// выбрасывает): квитанции уходят туда, AppendHead — без ошибки.
func TestR1Rev8ReceiptsPathSymlinkWritesElsewhere(t *testing.T) {
	key := receiptKey(t, 78)
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.jsonl")
	head := headOf(t, path)
	mustAppendHead(t, path, head, key, "a-1")
	private := filepath.Join(t.TempDir(), "tmp-of-the-esmcp-container")
	os.Remove(path)
	os.Symlink(private, path)
	if _, err := AppendHead(path, head, key, "esmcp", Draft{Time: at, Action: "a-2", Step: "intent"}); err != nil {
		t.Logf("refused: %v", err)
		return
	}
	got, _ := os.ReadFile(private)
	t.Errorf("the receipt went through the link to %s (%d bytes there), AppendHead reported success", private, len(got))
}

// R1-5. Разреженный хвост: противник 3 делает `truncate -s +8G receipts.jsonl`
// (места на диске это не берёт). Голова верна (endsAt — да), и AppendHead
// читает от неё до конца файла все 8 ГиБ нулей кусками по 1 МиБ (ReadLines:
// одна «длинная строка») — под flock, на действии агента. Так же сборщик
// (readFile) — в потоке репликации. Цена — ~3 ГБ/с; ext4 даёт файл до 16 ТиБ:
// `truncate -s +1T` после каждого действия — ~5 минут на каждое действие
// агента и столько же простоя входа сборщика. Дыры не содержат ни перевода
// строки, ни квитанции: их можно пропускать (SEEK_DATA).
func TestR1Rev8SparseTailStallsAppend(t *testing.T) {
	key := receiptKey(t, 79)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	head := headOf(t, path)
	mustAppendHead(t, path, head, key, "a-1")
	fi, _ := os.Stat(path)
	if err := os.Truncate(path, fi.Size()+8<<30); err != nil { // без перевода строки в конце: и «порванный хвост»
		t.Fatal(err)
	}
	start := time.Now()
	a := mustAppendHead(t, path, head, key, "a-2")
	took := time.Since(start)
	t.Logf("after an 8 GiB sparse extension: AppendHead took %v (seq %d, skipped %d)", took, a.Receipt.Seq, a.Skipped)
	if took > time.Second {
		t.Errorf("an 8 GiB hole, free for whoever writes the file, cost the gateway %v under flock; 1 TiB would cost ~%v per action", took, took*128)
	}
}
