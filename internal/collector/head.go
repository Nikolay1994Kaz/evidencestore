package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Сборщик — свидетель голов цепи (DECISIONS п. 31). Если хранилище и
// источник ведут разные люди, переписанную историю ловит сам сборщик.
//
// Каждый ответ хранилища несёт подписанную голову — контрольную точку: число
// звеньев и корень дерева над ними, — и доказательство, что она продолжает
// голову, которую сборщик назвал в запросе (checkpointHeader). Сборщик
// принимает голову, если её подписал закреплённый ключ хранилища, она не
// меньше прежней, при равном размере у неё тот же корень, а при большем
// сходится доказательство. Первую голову он принимает без доказательства —
// как и закреплённый ключ, при первом контакте.
//
// Принятая голова не чаще checkpoint_every ложится в checkpoint.json (с неё
// сборщик продолжает после перезапуска; при остановке — тоже) и затем в
// журнал голов checkpoints.jsonl со временем получения по часам сборщика —
// это свидетель для esverify -heads: время в нём — не слово хранилища. Сначала
// checkpoint.json: после падения между двумя записями сборщик продолжает с
// головы не старше последней строки журнала, и голова другой истории не
// ляжет в журнал между его головами.
//
// Голова, которая прежнюю не продолжает, — расхождение: обе подписаны
// хранилищем, и вместе они — улика против него. Они ложатся в
// checkpoints-conflict.jsonl, в журнал — ошибка; прежняя голова остаётся
// последней. Голова новее прежней без доказательства — предупреждение
// (доказательства нет, если у хранилища испорчен tree.hashes), но хранилище,
// которое дольше трёх checkpoint_every не показывает головы, продолжающей
// принятую (нет головы, нет доказательства), — ошибка: сборщик тем временем
// не свидетель. Всё это — не чаще checkpoint_every и никогда не останавливает
// доставку записей: ошибки записи файлов голов только в журнал (обнаружение
// не должно становиться риском для записей). Новую историю как законную
// (хранилище потеряло хвост цепи без копии наружу) принимает человек:
// останавливает сборщик и откладывает checkpoint.json и checkpoints.jsonl,
// файл расхождений остаётся уликой.

const (
	headFile         = "checkpoint.json"
	headsFile        = "checkpoints.jsonl"
	headConflictFile = "checkpoints-conflict.jsonl"
)

// headRecord — голова в checkpoint.json и строка журнала голов.
type headRecord struct {
	ReceivedAt time.Time         `json:"received_at"`
	Checkpoint *proof.Checkpoint `json:"checkpoint"`
}

// headConflict — строка checkpoints-conflict.jsonl.
type headConflict struct {
	ReceivedAt  time.Time         `json:"received_at"`
	Reason      string            `json:"reason"`
	Previous    *proof.Checkpoint `json:"previous"`
	Checkpoint  *proof.Checkpoint `json:"checkpoint"`
	Consistency [][]byte          `json:"consistency,omitempty"`
}

func (c *Collector) headPath() string { return filepath.Join(c.cfg.SpoolDir, headFile) }

// loadHead поднимает последнюю принятую голову и отрезает оборванные
// последние строки у файлов голов. Голова, которая не читается, не
// разбирается или которую не подписал закреплённый ключ (store_key сменили),
// откладывается вместе с журналом голов, и сборщик начинает как впервые: файлы
// голов вспомогательные, запуск и доставку они не останавливают (ошибки — в
// журнал), а журнал не смешивает головы двух историй.
func (c *Collector) loadHead() {
	for _, name := range []string{headsFile, headConflictFile} {
		if err := cutTornLine(filepath.Join(c.cfg.SpoolDir, name)); err != nil {
			c.log.Error("a torn last line of a head file in spool_dir is not cut", "file", name, "err", err)
		}
	}
	data, err := os.ReadFile(c.headPath())
	if errors.Is(err, os.ErrNotExist) {
		// checkpoint.json нет, а журнал голов есть (удалили один файл):
		// последняя голова — последняя строка журнала (он не впереди
		// checkpoint.json), иначе в журнал легла бы голова другой истории,
		// принятая на веру.
		tail, _, terr := readTail(filepath.Join(c.cfg.SpoolDir, headsFile))
		tail = bytes.TrimRight(tail, "\n")
		if errors.Is(terr, os.ErrNotExist) || terr == nil && len(tail) == 0 {
			return
		}
		data, err = tail[bytes.LastIndexByte(tail, '\n')+1:], terr
	}
	var r headRecord
	if err == nil {
		if err = json.Unmarshal(data, &r); err == nil {
			if r.Checkpoint == nil {
				err = errors.New("no head in it")
			} else {
				err = proof.VerifyCheckpoint(*r.Checkpoint, c.storeKey)
			}
		}
	}
	if err == nil {
		c.head = r.Checkpoint
		return
	}
	suffix := fmt.Sprintf(".unverified-%d", c.wall().Unix())
	c.log.Error("the last head of the store's chain in spool_dir cannot be read or does not verify with store_key: it is set aside with the head journal, and the next head is taken as the first one",
		"suffix", suffix, "err", err)
	for _, path := range []string{filepath.Join(c.cfg.SpoolDir, headsFile), c.headPath()} {
		if err := os.Rename(path, path+suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			c.log.Error("a head file in spool_dir is not set aside", "file", filepath.Base(path), "err", err)
		}
	}
}

// askHead называет хранилищу последнюю принятую голову: ответ докажет, что
// новая её продолжает.
func (c *Collector) askHead(req *http.Request) {
	if c.head != nil {
		req.Header.Set(checkpointHeader, strconv.FormatUint(c.head.Size, 10))
	}
}

// witness сверяет голову из ответа хранилища. Ошибки записи файлов голов —
// только в журнал: доставку записей они не останавливают.
func (c *Collector) witness(a headAnswer) {
	if err := c.witnessHead(a); err != nil {
		c.log.Error("a head of the store's chain was not written to spool_dir; records keep being delivered", "err", err)
	}
}

// markDown — запрос к хранилищу отказал (нет связи, ответ не 200): с первого
// отказа до следующего ответа отсчёт «нет головы» стоит.
func (c *Collector) markDown() {
	if c.headDown.IsZero() {
		c.headDown = c.now()
	}
}

// witnessHead сверяет голову из ответа хранилища с последней принятой.
// Ошибку отдаёт только запись на диск.
func (c *Collector) witnessHead(a headAnswer) error {
	now := c.now()
	if c.headSeen.IsZero() {
		c.headSeen, c.headGrewSent = now, c.sent // отсчёт «нет головы» — с первого ответа
	} else if !c.headDown.IsZero() {
		// Пока запросы к хранилищу отказывали, отсчёт стоял: после долгого
		// простоя оно вправе ответить без головы, пока его копия не прошла.
		// Промежуток между ответами простоем не считается — сборщик мог
		// просто не спрашивать (P-42).
		c.headSeen = c.headSeen.Add(now.Sub(c.headDown))
	}
	c.headDown = time.Time{}
	cp := a.Checkpoint
	if cp == nil {
		c.headMissing(now)
		return c.saveHeadDue(now)
	}
	if err := proof.VerifyCheckpoint(*cp, c.storeKey); err != nil {
		c.headAlert(now, "the store sent a head of its chain that does not verify with store_key; it is ignored", "err", err)
		c.headMissing(now)
		return c.saveHeadDue(now)
	}
	last := c.head
	var reason string
	switch {
	case last == nil:
	case cp.Size < last.Size:
		reason = fmt.Sprintf("the store's chain went back from %d links to %d", last.Size, cp.Size)
	case cp.Size == last.Size && !bytes.Equal(cp.Root, last.Root):
		reason = fmt.Sprintf("the store signed two different heads of %d links", cp.Size)
	case cp.Size == last.Size:
		// Та же голова — свежая, только пока сборщик ничего не доставил с тех
		// пор, как она выросла: доставленное ложится в звенья за тик цепи
		// (с копией — за replica.every), и хранилище, которое отвечает прежней
		// головой, замораживает свидетеля (P-37).
		if c.sent == c.headGrewSent {
			c.headSeen = now
		} else {
			c.headMissing(now)
		}
		return c.saveHeadDue(now)
	case len(a.Consistency) == 0:
		c.headAlert(now, "the store sent a newer head of its chain without a proof that it extends the last one; the last one is kept",
			"last", last.Size, "head", cp.Size)
		c.headMissing(now)
		return c.saveHeadDue(now)
	default:
		if err := proof.CheckExtends(*cp, *last, a.Consistency); err != nil {
			reason = err.Error()
		}
	}
	if reason != "" {
		c.headMissing(now)
		return errors.Join(c.headConflict(now, reason, last, cp, a.Consistency), c.saveHeadDue(now))
	}
	c.head, c.headDirty, c.headSeen, c.headGrewSent = cp, true, now, c.sent
	return c.saveHeadDue(now)
}

// saveHeadDue кладёт принятую голову на диск, если она ещё не там и с прошлой
// попытки прошло checkpoint_every. Неудача тоже считается попыткой: повтор —
// не раньше чем через checkpoint_every.
func (c *Collector) saveHeadDue(now time.Time) error {
	if !c.headDirty || !c.headSaved.IsZero() && now.Sub(c.headSaved) < c.cfg.CheckpointEvery.D() {
		return nil
	}
	c.headSaved = now
	if err := c.saveHead(); err != nil {
		return err
	}
	c.headDirty = false
	return nil
}

// saveHead кладёт последнюю принятую голову в checkpoint.json и в журнал
// голов — в этом порядке (см. шапку).
func (c *Collector) saveHead() error {
	r := headRecord{ReceivedAt: c.wall().UTC(), Checkpoint: c.head}
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return c.persist("heads", func() error {
		if err := writeJSON(c.headPath(), r); err != nil {
			return err
		}
		return appendHeadLine(filepath.Join(c.cfg.SpoolDir, headsFile), line)
	})
}

// headConflict — голова, которая не продолжает принятую: улика в
// checkpoints-conflict.jsonl и ошибка в журнал, не чаще checkpoint_every
// (неудачная запись — тоже).
func (c *Collector) headConflict(now time.Time, reason string, last, cp *proof.Checkpoint, consistency [][]byte) error {
	if !c.headAlarm.IsZero() && now.Sub(c.headAlarm) < c.cfg.CheckpointEvery.D() {
		return nil
	}
	c.headAlarm = now
	c.log.Error("the store's chain does not extend the head this collector holds: the store rewrote or lost its history; both heads are signed by the store and kept as evidence, records keep being delivered",
		"reason", reason, "file", headConflictFile)
	line, err := json.Marshal(headConflict{ReceivedAt: c.wall().UTC(), Reason: reason, Previous: last, Checkpoint: cp, Consistency: consistency})
	if err != nil {
		return err
	}
	return c.persist("conflict", func() error {
		return appendHeadLine(filepath.Join(c.cfg.SpoolDir, headConflictFile), line)
	})
}

// headMissing — хранилище не показало головы, продолжающей принятую: дольше
// трёх checkpoint_every — ошибка в журнал, не чаще checkpoint_every.
func (c *Collector) headMissing(now time.Time) {
	every := c.cfg.CheckpointEvery.D()
	if now.Sub(c.headSeen) <= 3*every || !c.headStale.IsZero() && now.Sub(c.headStale) < every {
		return
	}
	c.headStale = now
	c.log.Error("the store has not shown a head of its chain that extends the one this collector holds (its answers carry no head, or no proof): this collector does not witness the chain meanwhile",
		"since", now.Sub(c.headSeen).Round(time.Second))
}

// headAlert — предупреждение о голове, не чаще checkpoint_every.
func (c *Collector) headAlert(now time.Time, msg string, args ...any) {
	if !c.headWarned.IsZero() && now.Sub(c.headWarned) < c.cfg.CheckpointEvery.D() {
		return
	}
	c.log.Warn(msg, args...)
	c.headWarned = now
}

// closeHead — при остановке принятая голова, ещё не легшая на диск,
// записывается: после запуска сборщик продолжит с неё.
func (c *Collector) closeHead() {
	if !c.headDirty {
		return
	}
	if err := c.saveHead(); err != nil {
		c.log.Error("the last head of the store's chain was not written to spool_dir at stop", "err", err)
		return
	}
	c.headDirty = false
}

// appendHeadLine дописывает строку в файл голов; оборванную запись (место
// кончилось) отрезает: к обрывку приклеилась бы следующая строка.
func appendHeadLine(path string, line []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		return errors.Join(err, f.Close())
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return errors.Join(err, f.Truncate(fi.Size()), f.Close())
	}
	return errors.Join(f.Sync(), f.Close())
}

// cutTornLine отрезает последнюю строку файла голов без перевода строки
// (запись оборвало падение).
func cutTornLine(path string) error {
	tail, base, err := readTail(path)
	if errors.Is(err, os.ErrNotExist) || err == nil && (len(tail) == 0 || tail[len(tail)-1] == '\n') {
		return nil
	}
	if err != nil {
		return err
	}
	return os.Truncate(path, base+int64(bytes.LastIndexByte(tail, '\n')+1))
}

// readTail — последние до 64 КиБ файла и их смещение: файлы голов растут
// годами, а строка в них — сотни байт.
func readTail(path string) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	base := max(fi.Size()-64<<10, 0)
	tail := make([]byte, fi.Size()-base)
	if _, err := f.ReadAt(tail, base); err != nil {
		return nil, 0, err
	}
	return tail, base, nil
}
