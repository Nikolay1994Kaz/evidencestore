package pgtap

// Повторы ниже места входа. Сервер шлёт поток от позиции слота, а не от места
// входа (фиксации последней транзакции, лежащей в буфере целиком): база,
// поднятая из копии, пишет свои новые транзакции на места журнала, которые
// сборщик уже прочёл у прежней истории, и, попроси он поток от своего места,
// сервер их бы не прислал — правки людей и действия шлюза пропадали без
// записи и без тревоги (T-1, R2-3 второго захода). Ниже места входа повтор
// транзакции, которая уже в буфере, отличается от новой транзакции базы тем,
// что на её месте фиксации в справочнике лежит она же: тот же xid и то же
// время фиксации. Повтор не пишется снова (иначе последняя строка
// справочника о транзакции — отпечаток, и откат действия, которое пережило
// подъём, отказывал бы, R2-8); новая — пишется, а первая такая говорит, что
// база ушла назад (Config.Diverged).

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// seenTx — транзакция в буфере: номер и время фиксации.
type seenTx struct {
	xid uint32
	at  int64
}

// maxSeen — сколько транзакций буфера помнить для сверки повторов. Ниже
// самой старой из них сверять не с чем (floor): там повтор — по месту, как
// раньше.
var maxSeen = 1 << 20

// remember — транзакция легла в буфер на место фиксации final.
func (t *Tap) remember(final uint64, xid uint32, at time.Time) {
	if t.seen == nil {
		t.seen = map[uint64]seenTx{}
	}
	if _, ok := t.seen[final]; !ok {
		t.seenOrder = append(t.seenOrder, final)
	}
	t.seen[final] = seenTx{xid, at.UnixNano()}
	if len(t.seenOrder) > maxSeen {
		drop := t.seenOrder[:len(t.seenOrder)-maxSeen/2]
		for _, lsn := range drop {
			delete(t.seen, lsn)
			t.floor = max(t.floor, lsn+1)
		}
		t.seenOrder = append([]uint64(nil), t.seenOrder[len(drop):]...)
	}
}

// Resume — вход подключился и просит поток от позиции слота slot. До места
// входа на этот миг транзакции потока сверяются со справочником; rewound —
// база уже ушла назад (вход это увидел при подключении): транзакция ниже
// места, которую сверить не с чем, — новая, а не повтор.
func (t *Tap) Resume(slot uint64, rewound bool) error {
	t.recheck = t.lastCommit
	t.rewound = rewound
	if slot >= t.lastCommit || (t.loaded && slot+1 >= t.floor) {
		return nil
	}
	return t.loadSeen(slot)
}

// loadSeen читает справочник с конца: транзакции буфера с местом фиксации
// выше slot (и не выше места входа) — в seen.
func (t *Tap) loadSeen(slot uint64) error {
	f, err := os.Open(filepath.Join(t.cfg.Dir, IndexFile))
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	t.seen, t.seenOrder, t.loaded, t.floor = map[uint64]seenTx{}, nil, true, 0
	var found []struct {
		lsn uint64
		tx  seenTx
	}
	floor := uint64(0) // дошли до начала справочника: сверить можно всё
	stop := false
	each := func(line []byte) {
		var e struct {
			XID        uint32 `json:"xid"`
			CommitTime string `json:"commit_time"`
			CommitLSN  string `json:"commit_lsn"`
		}
		if json.Unmarshal(line, &e) != nil {
			return
		}
		lsn, err := pgwire.ParseLSN(e.CommitLSN)
		at, terr := time.Parse(time.RFC3339Nano, e.CommitTime)
		switch {
		case e.CommitLSN == "" || err != nil || terr != nil:
			// Строка отпечатка из пачки прежней версии: места в ней нет, и
			// ниже неё сверять не с чем.
			stop, floor = true, t.lowest(found)
		case uint64(lsn) <= slot:
			stop, floor = true, slot+1
		case uint64(lsn) > t.lastCommit:
			// Строка справочника легла, а последняя часть — нет (упал между
			// ними): в буфере её нет, сервер пришлёт её как новую.
		case len(found) >= maxSeen:
			stop, floor = true, t.lowest(found)
		default:
			found = append(found, struct {
				lsn uint64
				tx  seenTx
			}{uint64(lsn), seenTx{e.XID, at.UnixNano()}})
		}
	}
	const chunk = 1 << 20
	end := fi.Size()
	var carry []byte
	for end > 0 && !stop {
		start := max(0, end-chunk)
		buf := make([]byte, end-start, int(end-start)+len(carry))
		if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
			return err
		}
		buf = append(buf, carry...)
		end = start
		// Первая строка куска может начинаться в предыдущем: она — в carry.
		i := 0
		if start > 0 {
			i = bytes.IndexByte(buf, '\n') + 1
			if i == 0 {
				carry = buf
				continue
			}
		}
		lines := bytes.Split(bytes.TrimRight(buf[i:], "\n"), []byte("\n"))
		for k := len(lines) - 1; k >= 0 && !stop; k-- {
			if len(lines[k]) > 0 {
				each(lines[k])
			}
		}
		carry = buf[:i]
	}
	if len(carry) > 0 && !stop {
		each(bytes.TrimRight(carry, "\n"))
	}
	t.floor = floor
	for k := len(found) - 1; k >= 0; k-- { // в seenOrder — в порядке записи
		t.remember(found[k].lsn, found[k].tx.xid, time.Unix(0, found[k].tx.at))
	}
	if t.floor > slot+1 {
		t.log.Warn("the server sends the log from the replication slot, and the index holds what is in the spool only from a later place: "+
			"a transaction between them that the collector has is taken for a repeat by its place, as before",
			"slot", pgwire.LSN(slot).String(), "from", pgwire.LSN(t.floor).String())
	}
	return nil
}

// lowest — самое раннее место среди найденного; ничего — место входа + 1.
func (t *Tap) lowest(found []struct {
	lsn uint64
	tx  seenTx
}) uint64 {
	low := t.lastCommit + 1
	for _, f := range found {
		low = min(low, f.lsn)
	}
	return low
}

// resent решает о транзакции m ниже места входа: повтор того, что уже в
// буфере (dup), или новая транзакция базы. Первая новая ниже места, пока
// база не ушла назад, — Config.Diverged.
func (t *Tap) resent(xid uint32, final uint64, at time.Time) (dup bool, err error) {
	if final > max(t.recheck, t.lastCommit) {
		return false, nil
	}
	diverged := false
	if e, ok := t.seen[final]; ok {
		if e.xid == xid && e.at == at.UnixNano() {
			return true, nil
		}
		diverged = true // на этом месте в буфере другая транзакция
	} else if final >= t.floor && t.loaded {
		diverged = true // сверить есть с чем, а такой нет
	} else if !t.rewound {
		return true, nil // сверить не с чем: повтор по месту, как раньше
	}
	if diverged && !t.rewound {
		t.rewound = true
		if t.cfg.Diverged != nil {
			if err := t.cfg.Diverged(xid, final, max(t.recheck, t.lastCommit)); err != nil {
				return false, err
			}
		}
	}
	return false, nil
}

// PlaceTime — время фиксации транзакции на месте входа place, если она в
// seen: позднее время, прочитанное из прежней истории базы.
func (t *Tap) PlaceTime(place uint64) (time.Time, bool) {
	e, ok := t.seen[place]
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(0, e.at), true
}
