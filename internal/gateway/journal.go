package gateway

// Файл квитанций шлюза. Пишут его шлюзы (esmcp, esundo, esreceipt sign),
// иногда несколько процессов и несколько шлюзов сразу: каждая квитанция
// дописывается под flock, цепочка шлюза идёт от его последней квитанции в
// файле, подписанной его ключом, мимо чужих строк, и квитанция ложится на
// диск (fsync) до того, как Append вернётся.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Appended — что сделал Append: строка квитанции и что Append встретил в
// файле после прежней квитанции шлюза: Skipped — строк, которые не его
// квитанции; из них Claimed — от его имени с чужой подписью, Stale — его же
// квитанции не новее последней (копии прежних строк или вторая ветвь
// цепочки); Torn — последняя строка была порвана; Glued — квитанцию
// склеили с байтами, дописанными без flock, и она записана ещё раз.
type Appended struct {
	Line    []byte
	Receipt Receipt
	Skipped int
	Claimed int
	Stale   int
	Torn    bool
	Glued   bool
}

// Append подписывает шаг d квитанцией шлюза name и дописывает её в файл path.
//
// Где цепочка шлюза, Append узнаёт по метке в файле рядом (headsPath): место
// и хэш его последней квитанции. Метка — подсказка, а не правда: Append
// сверяет её с файлом и идёт от неё вперёд по сцепке, так что устаревшая или
// подложенная метка цепочку не раздвоит. Нет метки или не сходится — от
// последней квитанции шлюза в файле с большим seq (fallbackHead).
//
// Кто пишет в файл без ключа, шлюз не останавливает и цепочку не
// раздваивает (R1-2, R1-3): строки от имени шлюза с чужой подписью,
// строки длиннее любой квитанции и копии его прежних квитанций Append
// пропускает и называет в Appended. Ни одной своей квитанции, а строки от
// его имени есть — новая цепочка, а не отказ: отказ на каждой квитанции
// превращал одну подложенную строку в остановку шлюза; не тот ключ покажет
// хранилище (подпись не того ключа) и сборщик (forged-receipt).
//
// Порванная последняя строка (файл кончается не переводом строки: писавший
// умер посреди строки — все шлюзы пишут под flock) закрывается переводом
// строки и остаётся в файле поломанной строкой. Квитанция ложится на диск
// (fsync) до того, как Append вернётся.
func Append(path string, key ed25519.PrivateKey, name string, d Draft) (Appended, error) {
	s, err := NewSigner(key, name, nil)
	if err != nil {
		return Appended{}, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return Appended{}, err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return Appended{}, fmt.Errorf("gateway: lock %s: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		return Appended{}, err
	}
	size := st.Size()
	torn, err := tornTail(f)
	if err != nil {
		return Appended{}, err
	}
	pub := key.Public().(ed25519.PublicKey)
	c := chainScan{name: name, pub: pub}
	heads := readHeads(path)
	h, marked := heads[name]
	marked = marked && h.Key == hex.EncodeToString(pub)
	if marked && c.resume(f, h, size) {
		if err := c.scan(f, h.End, size); err != nil {
			return Appended{}, err
		}
	} else {
		if err := c.fallbackHead(f, size); err != nil {
			return Appended{}, err
		}
		if c.cur == nil && marked && h.Seq > 0 && h.Seq < MaxSeq-1 && isHash(h.Hash) {
			// Своих квитанций в файле нет, а метка есть: файл ротировали или
			// обрезали. Цепочка идёт дальше от последней квитанции — она уже
			// у сборщика и в хранилище, и новая цепочка у них была бы
			// поломкой на каждой ротации.
			c.cur = &receiptLink{hash: h.Hash, seq: h.Seq}
		}
	}
	if c.cur != nil {
		if c.cur.seq >= MaxSeq {
			return Appended{}, fmt.Errorf("gateway: the chain has reached seq %d", c.cur.seq)
		}
		s.next, s.prev = c.cur.seq+1, c.cur.hash
	}
	line, err := s.Sign(d)
	if err != nil {
		return Appended{}, err
	}
	out := append(bytes.Clone(line), '\n')
	if torn {
		out = append([]byte{'\n'}, out...)
	}
	if beforeWrite != nil {
		beforeWrite(path)
	}
	if _, err := f.Write(out); err != nil {
		return Appended{}, err
	}
	glued := false
	if !torn {
		// flock рекомендательный: кто пишет без него, мог дописать байты без
		// перевода строки между проверкой хвоста и записью — и квитанция
		// склеилась с ними, а намерение пропало (T-5). Тогда та же строка
		// ещё раз, с переводом строки впереди: одну запись с O_APPEND уже не
		// разорвать.
		if glued, err = gluedBefore(f, int64(len(out))); err != nil {
			return Appended{}, err
		}
		if glued {
			if _, err := f.Write(append([]byte{'\n'}, out...)); err != nil {
				return Appended{}, err
			}
		}
	}
	if err := f.Sync(); err != nil {
		return Appended{}, err
	}
	r, _ := ParseReceipt(line)
	// Место сразу за строкой: с O_APPEND запись легла в конец, каким он был
	// в тот миг, — после чужих байтов, если их дописали без flock.
	if end, err := f.Seek(0, io.SeekCurrent); err == nil {
		heads[name] = headMark{Key: hex.EncodeToString(pub), Seq: r.Seq, Hash: r.Hash, End: end}
		writeHeads(path, heads) // не вышло — следующий Append найдёт цепочку медленнее, но найдёт
	}
	return Appended{Line: line, Receipt: r, Skipped: c.skipped, Claimed: c.claimed, Stale: c.stale, Torn: torn, Glued: glued}, nil
}

// beforeWrite — для тестов: зовётся между проверкой хвоста и записью, там,
// где писатель без flock вклинивается (T-5).
var beforeWrite func(path string)

// gluedBefore — перед только что дописанными n байтами (запись кончается на
// текущем месте f) стоит не перевод строки: строка склеилась с чужими байтами.
func gluedBefore(f *os.File, n int64) (bool, error) {
	end, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return false, err
	}
	start := end - n
	if start <= 0 {
		return false, nil
	}
	one := make([]byte, 1)
	if _, err := f.ReadAt(one, start-1); err != nil {
		return false, err
	}
	return one[0] != '\n', nil
}

// tornTail — файл не пуст и кончается не переводом строки.
func tornTail(f *os.File) (bool, error) {
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return false, err
	}
	one := make([]byte, 1)
	if _, err := f.ReadAt(one, st.Size()-1); err != nil {
		return false, err
	}
	return one[0] != '\n', nil
}

// headMark — метка цепочки шлюза: его последняя квитанция и место сразу за
// её строкой в файле.
type headMark struct {
	Key  string `json:"key"` // открытый ключ шлюза, hex
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
	End  int64  `json:"end"`
}

// headsPath — файл меток рядом с файлом квитанций: скрытый и без
// «.jsonl» в имени, чтобы его не взял вход сборщика по маске.
func headsPath(path string) string {
	dir, base := filepath.Split(path)
	return filepath.Join(dir, "."+strings.ReplaceAll(base, ".", "_")+".heads")
}

func readHeads(path string) map[string]headMark {
	heads := map[string]headMark{}
	if data, err := os.ReadFile(headsPath(path)); err == nil && len(data) <= 1<<20 {
		json.Unmarshal(data, &heads)
	}
	if heads == nil {
		heads = map[string]headMark{}
	}
	return heads
}

// writeHeads заменяет файл меток целиком (временный файл и переименование)
// без fsync: метка лишь ускоряет поиск цепочки, потерянная метка ничего не
// ломает.
func writeHeads(path string, heads map[string]headMark) {
	data, err := json.Marshal(heads)
	if err != nil {
		return
	}
	hp := headsPath(path)
	if err := os.WriteFile(hp+".tmp", data, 0o640); err != nil {
		return
	}
	if err := os.Rename(hp+".tmp", hp); err != nil {
		os.Remove(hp + ".tmp")
	}
}

// chainScan ищет последнюю квитанцию шлюза name, подписанную ключом pub.
type chainScan struct {
	name string
	pub  ed25519.PublicKey
	cur  *receiptLink // последняя своя квитанция; nil — своих нет

	skipped, claimed, stale int
}

// resume — метка h сходится с файлом: строка, которая кончается в h.End, —
// квитанция шлюза с её seq и хэшем.
func (c *chainScan) resume(f *os.File, h headMark, size int64) bool {
	if h.End <= 0 || h.End > size {
		return false
	}
	lines := backLines{f: f, pos: h.End - 1}
	one := make([]byte, 1)
	if _, err := f.ReadAt(one, h.End-1); err != nil || one[0] != '\n' {
		return false
	}
	line, ok, err := lines.next()
	if err != nil || !ok || lines.long {
		return false
	}
	r, own, _ := c.own(line)
	if !own || r.Seq != h.Seq || r.Hash != h.Hash {
		return false
	}
	c.cur = &receiptLink{hash: r.Hash, seq: r.Seq}
	return true
}

// scan идёт по строкам файла от from до size вперёд и двигает цепочку только
// по сцепке: своя квитанция с seq на один больше и prev — хэш последней.
// Обрывок без перевода строки в конце — не строка: его дописывают или он
// порван.
func (c *chainScan) scan(f *os.File, from, size int64) error {
	return forwardLines(f, from, size, func(line []byte, long bool) {
		if long {
			c.skipped++
			return
		}
		r, own, claimed := c.own(line)
		switch {
		case !own:
			c.skipped++
			if claimed {
				c.claimed++
			}
		case c.cur == nil || (r.Seq == c.cur.seq+1 && r.Prev == c.cur.hash):
			c.take(r)
		default:
			c.skipped++
			c.stale++
		}
	})
}

// fallbackHead — метка не сходится с файлом: последняя квитанция шлюза
// с большим seq среди своих строк от конца файла до первой своей и ещё на
// fallbackSpan байт раньше неё. Копия прежней строки в конце (R1-2) так не
// становится последней: её настоящая преемница — раньше, в пределах окна.
func (c *chainScan) fallbackHead(f *os.File, size int64) error {
	if size == 0 {
		return nil
	}
	lines := backLines{f: f, pos: size}
	if torn, err := tornTail(f); err != nil {
		return err
	} else if !torn {
		lines.pos = size - 1
	} else if _, _, err := lines.next(); err != nil { // обрывок — не строка
		return err
	}
	var bestAt int64
	for {
		line, ok, err := lines.next()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		r, own, claimed := Receipt{}, false, false
		if !lines.long {
			r, own, claimed = c.own(line)
		}
		switch {
		case !own && c.cur == nil:
			// Строки после последней своей — в счёт, как у Append.
			c.skipped++
			if claimed {
				c.claimed++
			}
		case !own:
		case c.cur == nil:
			c.cur, bestAt = &receiptLink{hash: r.Hash, seq: r.Seq}, lines.pos
		case r.Seq > c.cur.seq:
			// Своя квитанция новее найденной в конце: та — копия прежней.
			c.cur = &receiptLink{hash: r.Hash, seq: r.Seq}
			c.stale++
		}
		if c.cur != nil && bestAt-lines.pos > fallbackSpan {
			return nil
		}
	}
}

// fallbackSpan — сколько байт раньше последней своей строки fallbackHead
// ищет квитанцию новее неё.
const fallbackSpan = 4 << 20

// own — строка — квитанция шлюза c.name с подписью его ключа; claimed —
// строка от его имени с другой подписью (или без неё).
func (c *chainScan) own(line []byte) (r Receipt, own, claimed bool) {
	if len(bytes.TrimSpace(line)) == 0 {
		return Receipt{}, false, false
	}
	r, _ = ParseReceipt(line)
	switch {
	case r.Gateway != c.name:
		return r, false, false
	case r.Seq == 0 || r.Prev == "" || r.Verify(c.pub) != nil:
		return r, false, true
	}
	return r, true, false
}

// take — своя квитанция r стала последней; счёт строк после неё — заново.
func (c *chainScan) take(r Receipt) {
	c.cur = &receiptLink{hash: r.Hash, seq: r.Seq}
	c.skipped, c.claimed, c.stale = 0, 0, 0
}

// forwardLines отдаёт строки файла от from до size кусками; строка длиннее
// любой квитанции отдаётся один раз как long, без байтов, — память не
// растёт с тем, что дописали в файл.
func forwardLines(f *os.File, from, size int64, each func(line []byte, long bool)) error {
	buf := make([]byte, 1<<20)
	var partial []byte
	long := false
	for off := from; off < size; {
		n := int64(len(buf))
		if size-off < n {
			n = size - off
		}
		got, err := f.ReadAt(buf[:n], off)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if got == 0 {
			break
		}
		off += int64(got)
		data := buf[:got]
		for len(data) > 0 {
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				if !long {
					partial = append(partial, data...)
					if len(partial) > 2*MaxReceiptLen {
						partial, long = nil, true
					}
				}
				break
			}
			if long {
				each(nil, true)
				long = false
			} else {
				each(append(partial, data[:i]...), false)
			}
			partial = partial[:0]
			data = data[i+1:]
		}
	}
	return nil
}

// backLines читает строки файла с конца. pos — где кончаются ещё не
// прочитанные байты; buf — прочитанные, но не отданные; long — отданная
// строка длиннее любой квитанции, её байты не отданы.
type backLines struct {
	f    *os.File
	pos  int64
	buf  []byte
	done bool
	long bool
}

func (b *backLines) next() ([]byte, bool, error) {
	b.long = false
	skipping := false
	for {
		if i := bytes.LastIndexByte(b.buf, '\n'); i >= 0 {
			line := b.buf[i+1:]
			b.buf = b.buf[:i]
			if skipping {
				b.long = true
				return nil, true, nil
			}
			return line, true, nil
		}
		if b.pos == 0 {
			if b.done {
				return nil, false, nil
			}
			b.done = true
			if skipping {
				b.long = true
				return nil, true, nil
			}
			return b.buf, true, nil
		}
		n := min(int64(64<<10), b.pos)
		chunk := make([]byte, n, int(n)+len(b.buf))
		if _, err := b.f.ReadAt(chunk, b.pos-n); err != nil {
			return nil, false, err
		}
		b.pos -= n
		if skipping {
			b.buf = chunk
		} else {
			b.buf = append(chunk, b.buf...)
		}
		if !skipping && len(b.buf) > 2*MaxReceiptLen && bytes.LastIndexByte(b.buf, '\n') < 0 {
			// Строка длиннее любой квитанции (R2-7): её байты не копятся,
			// строка отдаётся как long, и чтение идёт дальше.
			skipping, b.buf = true, nil
		}
	}
}

// GenerateKey пишет новый ключ шлюза в path (PKCS#8 PEM, права 0600) и
// отдаёт открытый. Файл, который уже есть, не трогается: чужой ключ,
// перезаписанный по ошибке, — потерянная цепочка.
func GenerateKey(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	return pub, f.Close()
}

// LoadKey читает ключ шлюза (PKCS#8 PEM, Ed25519).
func LoadKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: not a PKCS#8 PEM private key (esreceipt keygen writes one)", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return key, nil
}

// ValidName — годится ли s в имя шлюза (поле gateway квитанции).
func ValidName(s string) bool { return validName(s, MaxGatewayName) }
