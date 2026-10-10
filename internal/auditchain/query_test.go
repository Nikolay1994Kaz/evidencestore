package auditchain

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// chainOfLinks — n звеньев по одному листу в каждом.
func chainOfLinks(t *testing.T, dir string, n int) Head {
	t.Helper()
	c := mustOpen(t, dir)
	for i := 0; i < n; i++ {
		c.Append(leafN(i))
		if _, err := c.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	head := c.Head()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	return head
}

// ⭐TestMissingLeavesAreLoud — листья не удаляются никогда, и пропавший файл
// листьев — потеря, а не «срок хранения». В ядре, откуда пришёл этот код,
// пропажа считалась штатной; для улик она обязана быть ошибкой у всех
// читателей, иначе стёртые снаружи улики выглядели бы как истёкшие.
func TestMissingLeavesAreLoud(t *testing.T) {
	dir := t.TempDir()
	c := mustOpen(t, dir)
	c.segmentBytes = 1 // каждый тик — свой файл листьев
	for i := 0; i < 4; i++ {
		c.Append(leafN(i))
		if _, err := c.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	c.Close()

	// ПАРНЫЙ КОНТРОЛЬ: пока файлы на месте, видно всё.
	links, err := ReadChain(dir)
	if err != nil || len(links) != 4 {
		t.Fatalf("звеньев %d, %v", len(links), err)
	}
	var seen int
	if err := ScanVerifiedLeaves(dir, links, func(uint64, Leaf) error { seen++; return nil }); err != nil || seen != 4 {
		t.Fatalf("до пропажи: прочитано %d, %v", seen, err)
	}
	segs, err := leafSegments(dir)
	if err != nil || len(segs) != 4 {
		t.Fatalf("файлов листьев %d, %v", len(segs), err)
	}

	// Пропал файл в середине: листья ищутся в соседнем и не находятся.
	// Пропал самый старый: искать не в чем. Пропал последний: звено
	// обещает листья, которых нет. Все случаи — ErrLeavesMissing. Каждый
	// случай — отдельно: пропавший файл возвращается на место.
	for _, gone := range []int{2, 0, 3} {
		p := leafPath(dir, segs[gone])
		if err := os.Rename(p, p+".away"); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadLeaves(dir, segs[gone], 1); !errors.Is(err, ErrLeavesMissing) {
			t.Errorf("файл %d: ReadLeaves: %v", gone, err)
		}
		if err := ScanVerifiedLeaves(dir, links, func(uint64, Leaf) error { return nil }); !errors.Is(err, ErrLeavesMissing) {
			t.Errorf("файл %d: ScanVerifiedLeaves: %v", gone, err)
		}
		if err := os.Rename(p+".away", p); err != nil {
			t.Fatal(err)
		}
	}
	// Пропали все файлы листьев: носитель не начинает с чистого листа.
	for _, first := range segs {
		if err := os.Remove(leafPath(dir, first)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Open(dir); !errors.Is(err, ErrLeavesMissing) {
		t.Errorf("все листья пропали, Open: %v", err)
	}
}

// ⭐TestLeafTamperIsSeenOnScan — лист подменён вместе с CRC кадра: кадр
// цел, но корень звена не сходится. Сверка корней при чтении это видит
// (раньше не видел никто, кроме сборки пакета по этому звену).
func TestLeafTamperIsSeenOnScan(t *testing.T) {
	dir := t.TempDir()
	c := mustOpen(t, dir)
	for i := 0; i < 3; i++ {
		c.Append(leafN(i))
	}
	if _, err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	links, err := ReadChain(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaves, err := ReadLeaves(dir, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	leaves[1].Subject = "подменён"
	var buf []byte
	for _, l := range leaves {
		buf = append(buf, frameLeaf(l)...)
	}
	if err := os.WriteFile(leafPath(dir, 0), buf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ScanLeaves(dir, func(uint64, Leaf) error { return nil }); err != nil {
		t.Fatalf("ПАРНЫЙ КОНТРОЛЬ: кадры целы, а ScanLeaves отказал: %v", err)
	}
	if err := ScanVerifiedLeaves(dir, links, func(uint64, Leaf) error { return nil }); err == nil {
		t.Fatal("подменённый лист прошёл сверку с корнем")
	}
}

// ⭐TestScan_LoudOnCorruptLeafFile — порча ФАЙЛА ЛИСТЬЕВ — громкая
// ошибка, и не та, что у пропажи.
//
// ⚠Первая версия этого набора портила chain.log и была зелёной по неверной
// причине: ошибку возвращал ReadChain, а чтение листьев оставалось
// непроверенным.
func TestScan_LoudOnCorruptLeafFile(t *testing.T) {
	dir := t.TempDir()
	c := mustOpen(t, dir)
	for i := 0; i < 3; i++ {
		c.Append(leafN(i))
	}
	if _, err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	c.Close()

	// ПАРНЫЙ КОНТРОЛЬ: до порчи листья читаются.
	links, err := ReadChain(dir)
	if err != nil {
		t.Fatal(err)
	}
	scan := func() error { return ScanVerifiedLeaves(dir, links, func(uint64, Leaf) error { return nil }) }
	if err := scan(); err != nil {
		t.Fatalf("до порчи: %v", err)
	}

	// Портим тело кадра ВНУТРИ файла листьев, не трогая цепь.
	path := leafPath(dir, 0)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[12] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	err = scan()
	if err == nil {
		t.Fatal("порча файла листьев принята молча")
	}
	if errors.Is(err, ErrLeavesMissing) {
		t.Fatalf("порча названа пропажей: %v", err)
	}
}

// Порча ЗВЕНА в середине цепи — громкая ошибка и у читателя, и у носителя;
// носитель при этом ничего не режет (раньше считал всё после порчи
// оборванным хвостом и стирал).
func TestChainCorruptionIsLoud(t *testing.T) {
	for name, at := range map[string]int{"тело звена": 10, "длина кадра": 1} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			chainOfLinks(t, dir, 3)
			path := filepath.Join(dir, chainFileName)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data[at] ^= 0xff // в длине: заявлено больше, чем есть в файле
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadChain(dir); err == nil {
				t.Fatal("порча цепи принята читателем молча")
			}
			if _, err := Open(dir); err == nil {
				t.Fatal("порча цепи принята носителем молча")
			}
			if after, _ := os.ReadFile(path); len(after) != len(data) {
				t.Fatalf("цепь обрезана: %d байт, было %d", len(after), len(data))
			}
		})
	}
}
