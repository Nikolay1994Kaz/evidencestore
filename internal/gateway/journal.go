package gateway

// Файл квитанций шлюза. Пишут его шлюзы (esmcp, esundo, esreceipt sign),
// иногда несколько процессов и несколько шлюзов сразу: каждая квитанция
// дописывается под flock и ложится на диск (fsync) до того, как Append
// вернётся. Где цепочка шлюза, Append знает по голове (Head) — состоянию
// шлюза, которое лежит там же, где его ключ, а не рядом с файлом квитанций.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

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

// Head — голова цепочки шлюза: его последняя квитанция в файле квитанций.
// Это состояние шлюза, как его ключ, и лежать оно должно там, куда пишет
// только он (DefaultHead — рядом с ключом). Метку рядом с файлом квитанций
// подкладывал тот, кто пишет в его каталог без ключа: раздваивал цепочку,
// останавливал шлюз (seq у предела), затирал через ссылку его файлы (R1-1,
// R1-2, R1-3 второго захода).
type Head struct {
	Receipts string `json:"receipts"` // файл квитанций, абсолютный путь
	Gateway  string `json:"gateway"`
	Key      string `json:"key"` // открытый ключ шлюза, hex
	Seq      uint64 `json:"seq"`
	Hash     string `json:"hash"`
	End      int64  `json:"end"` // подсказка: место сразу за строкой квитанции в файле
}

// DefaultHead — файл головы цепочки шлюза name в файле квитанций receipts:
// рядом с ключом keyPath, свой у каждой пары «файл, шлюз».
func DefaultHead(keyPath, receipts, name string) string {
	abs, err := filepath.Abs(receipts)
	if err != nil {
		abs = receipts
	}
	sum := sha256.Sum256([]byte(abs + "\x00" + name))
	return keyPath + ".head-" + hex.EncodeToString(sum[:8])
}

// Append — AppendHead без головы: цепочка — по файлу (fallbackHead) при
// каждой квитанции. Для тестов и шлюзов, у которых своего каталога нет;
// шлюзы продукта ведут голову.
func Append(path string, key ed25519.PrivateKey, name string, d Draft) (Appended, error) {
	return AppendHead(path, "", key, name, d)
}

// AppendHead подписывает шаг d квитанцией шлюза name и дописывает её в файл
// path; head — файл головы цепочки (Head), пусто — без головы.
//
// С головой цепочка идёт от неё и ниже не опускается: обрезанный, заменённый
// или ротированный файл квитанций её не сбивает (квитанции до обрезки уже у
// сборщика и в хранилище). Файл читается только вперёд от головы — своя
// квитанция, сцепленная с ней, двигает её (шлюз упал между записью
// квитанции и головы). Без головы — своя квитанция с большим seq у конца
// файла (fallbackHead), и после записи голова заводится.
//
// Кто пишет в файл квитанций без ключа, шлюз не останавливает и цепочку не
// раздваивает: строки от имени шлюза с чужой подписью, строки длиннее любой
// квитанции и копии его прежних квитанций Append пропускает и называет в
// Appended. Своих квитанций нет, а строки от его имени есть — новая цепочка,
// а не отказ (отказ превращал одну подложенную строку в остановку шлюза); не
// тот ключ покажут хранилище и сборщик.
//
// Порванная последняя строка (писавший умер посреди строки — все шлюзы
// пишут под flock) закрывается переводом строки и остаётся в файле
// поломанной строкой. Квитанция ложится на диск до того, как Append
// вернётся; голова — тоже, и не записалась она — ошибка: без неё шлюз снова
// беззащитен перед обрезкой файла.
func AppendHead(path, head string, key ed25519.PrivateKey, name string, d Draft) (Appended, error) {
	s, err := NewSigner(key, name, nil)
	if err != nil {
		return Appended{}, err
	}
	abs, err := filepath.Abs(path)
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
	c := newChainScan(name, pub)
	var h Head
	trusted := false
	if head != "" {
		if h, trusted, err = readHead(head); err != nil {
			return Appended{}, err
		}
		trusted = trusted && h.Receipts == abs && h.Gateway == name && h.Key == hex.EncodeToString(pub) && h.Seq > 0 && isHash(h.Hash)
	}
	if trusted {
		c.cur = &receiptLink{hash: h.Hash, seq: h.Seq}
		from := int64(0)
		if c.endsAt(f, h, size) {
			from, c.counting = h.End, true
		}
		if err := c.scan(f, from, size); err != nil {
			return Appended{}, err
		}
	} else if err := c.fallbackHead(f, size); err != nil {
		return Appended{}, err
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
	a := Appended{Line: line, Receipt: r, Skipped: c.skipped, Claimed: c.claimed, Stale: c.stale, Torn: torn, Glued: glued}
	if head != "" {
		// Место сразу за строкой: с O_APPEND запись легла в конец, каким он
		// был в тот миг, — после чужих байтов, если их дописали без flock.
		end, err := f.Seek(0, io.SeekCurrent)
		if err == nil {
			err = writeHead(head, Head{Receipts: abs, Gateway: name, Key: hex.EncodeToString(pub), Seq: r.Seq, Hash: r.Hash, End: end})
		}
		if err != nil {
			return a, fmt.Errorf("gateway: the receipt is in %s, but the head of the chain %s could not be saved: %w", path, head, err)
		}
	}
	return a, nil
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

// maxHead — больше файл головы быть не может.
const maxHead = 4 << 10

// readHead читает голову цепочки; ok == false — головы нет. Не обычный файл
// (ссылка, FIFO) или файл больше головы — ошибка: голову пишет только шлюз.
func readHead(path string) (h Head, ok bool, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return h, false, nil
	}
	if err != nil {
		return h, false, fmt.Errorf("gateway: the head of the chain %s: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return h, false, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxHead {
		return h, false, fmt.Errorf("gateway: the head of the chain %s is not a file of the gateway (%s, %d bytes)", path, fi.Mode().Type(), fi.Size())
	}
	data, err := io.ReadAll(io.LimitReader(f, maxHead+1))
	if err != nil {
		return h, false, err
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return Head{}, false, nil // недописанная голова после падения: цепочка — по файлу
	}
	return h, true, nil
}

// writeHead заменяет голову целиком: временный файл (свой, O_EXCL),
// fsync, переименование.
func writeHead(path string, h Head) error {
	data, err := json.Marshal(h)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// chainScan ищет последнюю квитанцию шлюза name, подписанную ключом pub.
type chainScan struct {
	name   string
	pub    ed25519.PublicKey
	needle []byte       // "gateway":"<имя>": без него строка не его — и не разбирается
	cur    *receiptLink // последняя своя квитанция; nil — своих нет
	// counting — строки после головы считаются в Skipped, Claimed, Stale;
	// без места головы в файле (файл обрезан или заменён) прежние свои
	// строки — история, а не копии.
	counting bool

	skipped, claimed, stale int
}

func newChainScan(name string, pub ed25519.PublicKey) chainScan {
	return chainScan{name: name, pub: pub, needle: []byte(`"gateway":"` + name + `"`)}
}

// endsAt — строка, которая кончается в h.End, — квитанция шлюза с её seq и
// хэшем: читать вперёд можно от этого места.
func (c *chainScan) endsAt(f *os.File, h Head, size int64) bool {
	if h.End <= 0 || h.End > size {
		return false
	}
	one := make([]byte, 1)
	if _, err := f.ReadAt(one, h.End-1); err != nil || one[0] != '\n' {
		return false
	}
	lines := backLines{f: f, pos: h.End - 1}
	line, ok, err := lines.next()
	if err != nil || !ok || lines.long {
		return false
	}
	r, own, _ := c.own(line)
	return own && r.Seq == h.Seq && r.Hash == h.Hash
}

// scan идёт по строкам файла от from до size вперёд и двигает цепочку только
// по сцепке: своя квитанция с seq на один больше и prev — хэш последней.
func (c *chainScan) scan(f *os.File, from, size int64) error {
	_, err := ReadLines(f, from, size, func(line []byte, _ int64, long bool) {
		if long {
			c.count(true, false, false)
			return
		}
		r, own, claimed := c.own(line)
		switch {
		case !own:
			c.count(len(bytes.TrimSpace(line)) > 0, claimed, false)
		case c.cur == nil || (r.Seq == c.cur.seq+1 && r.Prev == c.cur.hash):
			c.take(r)
		default:
			c.count(true, false, true)
		}
	})
	return err
}

func (c *chainScan) count(skipped, claimed, stale bool) {
	if !c.counting {
		return
	}
	if skipped {
		c.skipped++
	}
	if claimed {
		c.claimed++
	}
	if stale {
		c.stale++
	}
}

// fallbackHead — головы нет: последняя квитанция шлюза с большим seq среди
// своих строк от конца файла до первой своей и ещё на fallbackSpan байт
// раньше неё. Копия прежней строки в конце так не становится последней: её
// настоящая преемница — раньше, в пределах окна.
func (c *chainScan) fallbackHead(f *os.File, size int64) error {
	if size == 0 {
		return nil
	}
	c.counting = true
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
			c.count(lines.long || len(bytes.TrimSpace(line)) > 0, claimed, false)
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
	if !bytes.Contains(line, c.needle) {
		return Receipt{}, false, false // не его: чужой шлюз или мусор, разбирать незачем (R1-6)
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

// ReadLines отдаёт строки файла f от from до size кусками: строка длиннее
// любой квитанции отдаётся один раз как long, без байтов, — память не растёт
// с тем, что дописали в файл. end — место сразу за строкой. Обрывок без
// перевода строки в конце не отдаётся: его дописывают или он порван; done —
// место сразу за последней отданной строкой.
func ReadLines(f *os.File, from, size int64, each func(line []byte, end int64, long bool)) (done int64, err error) {
	done = from
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
			return done, err
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
			end := off - int64(len(data)) + int64(i) + 1
			if long {
				each(nil, end, true)
				long = false
			} else {
				each(append(partial, data[:i]...), end, false)
			}
			partial, done = partial[:0], end
			data = data[i+1:]
		}
	}
	return done, nil
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
