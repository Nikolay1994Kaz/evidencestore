package keyring

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Формат keyring.dat:
//
//	"KRNG3\n" | u16 len | rootID | u16 len | wrapped | nonce(12) | GCM(fileKey, body, aad = всё, что до nonce)
//
//	wrapped = RootStore.Wrap(rootID, fileKey, aad = "KRNG3\n" | u16 len | rootID)
//
//	body:  u64 gen | u64 safe | u32 n | { str rootID }… | u32 n | { entry }…
//	entry: str scope | kekID(16) | u8 state | u64 gen
//	       | i64 deactivated | i64 destroyAfter | i64 destroyed | i64 effective
//	       | u8 n | { str approver }… | key(32, кроме Destroyed)
//	str:   u32 len | байты
//
// Числа big-endian, время — unix-нс, 0 — «ещё не было». rootID лежит открыто:
// без него не узнать, каким корнем отпирать. Он же входит в AAD, поэтому
// подменить его незаметно нельзя.
//
// Корень заворачивает только ключ файла — 32 байта, новые при каждой
// записи, — а не сам файл: HSM и KMS рассчитаны на ключи, а не на данные
// (у AWS KMS Encrypt предел 4096 байт), keyring.dat же растёт с каждым
// месяцем каждого источника, надгробия не удаляются. Уничтожен корень —
// ключ файла не развернуть, и файл не открыть.
//
// safe — последнее поколение, чья копия в резерве подтверждена к моменту
// записи. Своё поколение файл подтвердить не может, поэтому safe отстаёт на
// запись: после рестарта ключи из последней записи переподтверждаются.

func (k *Keyring) load(data []byte) error {
	if bytes.HasPrefix(data, []byte(legacyMagic)) {
		return fmt.Errorf("%w: %s: format KRNG2 is not read any more (prototype data: run `evidencestore init` again)", ErrCorrupt, k.path)
	}
	if len(data) < len(fileMagic)+2 || string(data[:len(fileMagic)]) != fileMagic {
		return fmt.Errorf("%w: %s: bad magic", ErrCorrupt, k.path)
	}
	n := int(binary.BigEndian.Uint16(data[len(fileMagic):]))
	idEnd := len(fileMagic) + 2 + n
	if n == 0 || n > maxRootIDLen || len(data) < idEnd+2 {
		return fmt.Errorf("%w: %s: bad header", ErrCorrupt, k.path)
	}
	rootID := string(data[len(fileMagic)+2 : idEnd])
	w := int(binary.BigEndian.Uint16(data[idEnd:]))
	hdrLen := idEnd + 2 + w
	if w == 0 || w > maxWrappedLen || len(data) < hdrLen {
		return fmt.Errorf("%w: %s: bad header", ErrCorrupt, k.path)
	}
	fileKey, err := k.roots.Unwrap(rootID, data[idEnd+2:hdrLen], data[:idEnd])
	if err != nil {
		// %w дважды: снаружи видны и «файл не открыть», и причина (нет корня?).
		return fmt.Errorf("%w: %s: root %s: %w", ErrCorrupt, k.path, rootID, err)
	}
	defer zeroize(fileKey)
	aead, err := newAEAD(fileKey)
	if err != nil {
		return fmt.Errorf("%w: %s: file key: %v", ErrCorrupt, k.path, err)
	}
	body, _, err := openNext(aead, data[hdrLen:], len(data)-hdrLen-aead.NonceSize(), data[:hdrLen])
	if err != nil {
		return fmt.Errorf("%w: %s: body: %v", ErrCorrupt, k.path, err)
	}
	defer zeroize(body) // в body открытые ключи всех скоупов
	k.rootID = rootID
	return k.decodeBody(body)
}

func (k *Keyring) decodeBody(body []byte) error {
	d := &dec{b: body}
	k.gen = d.u64()
	k.safe = d.u64()
	for n := d.u32(); n > 0 && d.err == nil; n-- {
		k.retired = append(k.retired, d.str(maxRootIDLen))
	}
	for n := d.u32(); n > 0 && d.err == nil; n-- {
		e := &entry{scope: d.str(MaxScopeLen)}
		copy(e.id[:], d.take(kekIDSize))
		e.state = State(d.u8())
		e.gen = d.u64()
		e.changed = k.gen // что из файла уже в резерве, файл сам не знает
		e.deactivated = d.time()
		e.destroyAfter = d.time()
		e.destroyed = d.time()
		e.effective = d.time()
		approvals := d.u8()
		if d.err == nil && approvals > MaxApprovals {
			return fmt.Errorf("%w: %d approvals", ErrCorrupt, approvals)
		}
		for ; approvals > 0 && d.err == nil; approvals-- {
			e.approvals = append(e.approvals, d.str(MaxApproverLen))
		}
		if e.live() {
			e.key = append([]byte(nil), d.take(kekSize)...) // копия: body обнулим
		}
		if d.err != nil {
			break
		}
		if e.scope == "" || e.state < Active || e.state > Destroyed {
			return fmt.Errorf("%w: bad entry %q", ErrCorrupt, e.scope)
		}
		if err := k.add(e); err != nil {
			return err
		}
	}
	if d.err != nil {
		return d.err
	}
	if len(d.b) != 0 {
		return fmt.Errorf("%w: %d trailing bytes", ErrCorrupt, len(d.b))
	}
	return nil
}

// persistLocked переписывает файл целиком под текущим корнем и копирует его
// в резерв.
//
// committed — заменён ли файл на диске. Если нет, операция не состоялась, и
// вызывающий откатывает память. Если да, память уже совпадает с диском и
// откатывать её нельзя, даже при err != nil (не прошла копия или fsync
// каталога): откат развёл бы память и диск, а корень нового файла остался
// бы сиротой, которую никто не уничтожит.
//
// На время копии mu отпускается: резерв бывает медленным (сеть), и Seal под
// уже скопированными ключами ждать его не должен. Вызывающий держит wmu,
// поэтому состояние в этом окне не меняется, а новый ключ Seal не выдаст,
// пока safe его не догонит.
func (k *Keyring) persistLocked() (committed bool, err error) {
	k.gen++ // пропуски номеров после сбоев безвредны
	body := k.encodeBodyLocked()
	defer zeroize(body)
	fileKey := make([]byte, fileKeySize)
	defer zeroize(fileKey)
	rand.Read(fileKey)
	hdr := []byte(fileMagic)
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(k.rootID)))
	hdr = append(hdr, k.rootID...)
	wrapped, err := k.roots.Wrap(k.rootID, fileKey, hdr)
	if err != nil {
		return false, fmt.Errorf("keyring wrap: %w", err)
	}
	if len(wrapped) == 0 || len(wrapped) > maxWrappedLen {
		return false, fmt.Errorf("keyring wrap: %d bytes, expected 1..%d", len(wrapped), maxWrappedLen)
	}
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(wrapped)))
	hdr = append(hdr, wrapped...)
	aead, err := newAEAD(fileKey)
	if err != nil {
		return false, err
	}
	data := appendSealed(bytes.Clone(hdr), aead, body, hdr)
	if committed, err := writeFileAtomic(k.path, data); err != nil {
		return committed, err
	}
	return true, k.backupLocked()
}

// backupLocked копирует текущий файл в резерв и двигает safe. Общий замок на
// время копии отпускается (см. persistLocked); вызывающий держит wmu.
func (k *Keyring) backupLocked() error {
	gen := k.gen
	if k.opt.Backup != nil {
		k.mu.Unlock()
		err := k.opt.Backup(k.path, gen)
		k.mu.Lock()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrBackupPending, err)
		}
	}
	k.safe = gen
	return nil
}

func (k *Keyring) encodeBodyLocked() []byte {
	// Размер считаем заранее: буфер не перевыделяется и не оставляет в куче
	// необнулённых копий ключей.
	size := 8 + 8 + 4 + 4
	for _, r := range k.retired {
		size += 4 + len(r)
	}
	for _, e := range k.byName {
		size += 4 + len(e.scope) + kekIDSize + 1 + 5*8 + 1
		for _, a := range e.approvals {
			size += 4 + len(a)
		}
		if e.live() {
			size += kekSize
		}
	}
	b := make([]byte, 0, size)
	b = binary.BigEndian.AppendUint64(b, k.gen)
	b = binary.BigEndian.AppendUint64(b, k.safe)
	b = binary.BigEndian.AppendUint32(b, uint32(len(k.retired)))
	for _, r := range k.retired {
		b = appendStr(b, r)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(k.byName)))
	for _, e := range k.byName {
		b = appendStr(b, e.scope)
		b = append(b, e.id[:]...)
		b = append(b, byte(e.state))
		b = binary.BigEndian.AppendUint64(b, e.gen)
		b = appendTime(b, e.deactivated)
		b = appendTime(b, e.destroyAfter)
		b = appendTime(b, e.destroyed)
		b = appendTime(b, e.effective)
		b = append(b, byte(len(e.approvals))) // предел MaxApprovals проверен в approve
		for _, a := range e.approvals {
			b = appendStr(b, a)
		}
		// По live(), а не по key != nil: при повороте корня ключ ещё лежит в
		// памяти на случай отката, но в новый файл попасть не должен.
		if e.live() {
			b = append(b, e.key...)
		}
	}
	return b
}

func appendStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func appendTime(b []byte, t time.Time) []byte {
	var ns int64
	if !t.IsZero() {
		ns = t.UnixNano()
	}
	return binary.BigEndian.AppendUint64(b, uint64(ns))
}

// dec читает body. Первая нехватка байтов запоминается в err, дальше все
// чтения отдают нули: ошибку достаточно проверить в конце записи.
type dec struct {
	b   []byte
	err error
}

func (d *dec) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n > len(d.b) {
		d.err = fmt.Errorf("%w: truncated body", ErrCorrupt)
		return nil
	}
	p := d.b[:n]
	d.b = d.b[n:]
	return p
}

func (d *dec) u8() uint8 {
	if p := d.take(1); p != nil {
		return p[0]
	}
	return 0
}

func (d *dec) u32() uint32 {
	if p := d.take(4); p != nil {
		return binary.BigEndian.Uint32(p)
	}
	return 0
}

func (d *dec) u64() uint64 {
	if p := d.take(8); p != nil {
		return binary.BigEndian.Uint64(p)
	}
	return 0
}

// str читает строку с префиксом длины. limit тот же, что при записи.
func (d *dec) str(limit int) string {
	n := d.u32()
	if d.err == nil && n > uint32(limit) {
		d.err = fmt.Errorf("%w: string length %d exceeds %d", ErrCorrupt, n, limit)
	}
	return string(d.take(int(n)))
}

func (d *dec) time() time.Time {
	if ns := int64(d.u64()); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
}

// writeFileAtomic: tmp → fsync → rename → fsync каталога. Снаружи виден либо
// старый файл, либо новый целиком. renamed — новый файл уже на месте; это
// так и тогда, когда не прошёл только fsync каталога.
func writeFileAtomic(path string, data []byte) (renamed bool, err error) {
	tmp := path + ".tmp"
	if err := writeSync(tmp, data); err != nil {
		os.Remove(tmp) // в нём тоже ключи, пусть и под корнем
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return false, fmt.Errorf("keyring rename: %w", err)
	}
	return true, syncDir(filepath.Dir(path))
}

func writeSync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("keyring write: %w", err)
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return fmt.Errorf("keyring write %s: %w", path, err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("keyring dir open: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("keyring dir fsync: %w", err)
	}
	return nil
}
