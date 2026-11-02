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
// Последняя принятая голова не чаще checkpoint_every ложится в
// checkpoint.json (с неё сборщик продолжает после перезапуска) и в журнал
// голов checkpoints.jsonl со временем получения по часам сборщика — это
// свидетель для esverify -heads: время в нём — не слово хранилища.
//
// Голова, которая прежнюю не продолжает, — расхождение: обе подписаны
// хранилищем, и вместе они — улика против него. Они ложатся в
// checkpoints-conflict.jsonl, в журнал — ошибка; прежняя голова остаётся
// последней, а записи доставляются дальше: остановка превратила бы
// обнаружение в риск для записей. Голова новее прежней без доказательства —
// предупреждение, не расхождение (доказательства нет, если у хранилища
// испорчен tree.hashes): прежняя остаётся. И то, и другое говорится не чаще
// checkpoint_every. Новую историю как законную (хранилище потеряло хвост цепи
// без копии наружу) принимает человек: удаляет checkpoint.json, файл
// расхождений остаётся уликой.

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

// loadHead поднимает последнюю принятую голову. Голова, которую не
// подписал закреплённый ключ (store_key сменили), откладывается в
// checkpoint.json.unverified, и сборщик начинает как впервые: доставку она
// не останавливает.
func (c *Collector) loadHead() error {
	var r headRecord
	found, err := readJSON(c.headPath(), &r)
	if err != nil || !found {
		return err
	}
	if r.Checkpoint == nil {
		return fmt.Errorf("collector: %s holds no head", headFile)
	}
	if err := proof.VerifyCheckpoint(*r.Checkpoint, c.storeKey); err != nil {
		c.log.Error("the last head of the store's chain in spool_dir does not verify with store_key: it is set aside, and the next head is taken as the first one",
			"file", headFile+".unverified", "err", err)
		return os.Rename(c.headPath(), c.headPath()+".unverified")
	}
	c.head = r.Checkpoint
	return nil
}

// askHead называет хранилищу последнюю принятую голову: ответ докажет, что
// новая её продолжает.
func (c *Collector) askHead(req *http.Request) {
	if c.head != nil {
		req.Header.Set(checkpointHeader, strconv.FormatUint(c.head.Size, 10))
	}
}

// witnessHead сверяет голову из ответа хранилища с последней принятой.
// Ошибку отдаёт только запись на диск.
func (c *Collector) witnessHead(a headAnswer) error {
	cp := a.Checkpoint
	if cp == nil {
		return nil
	}
	now := c.now()
	if err := proof.VerifyCheckpoint(*cp, c.storeKey); err != nil {
		c.headAlert(now, "the store sent a head of its chain that does not verify with store_key; it is ignored", "err", err)
		return nil
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
		return nil
	case len(a.Consistency) == 0:
		c.headAlert(now, "the store sent a newer head of its chain without a proof that it extends the last one; the last one is kept",
			"last", last.Size, "head", cp.Size)
		return nil
	default:
		if err := proof.CheckExtends(*cp, *last, a.Consistency); err != nil {
			reason = err.Error()
		}
	}
	if reason != "" {
		return c.headConflict(now, reason, last, cp, a.Consistency)
	}
	c.head = cp
	if !c.headSaved.IsZero() && now.Sub(c.headSaved) < c.cfg.CheckpointEvery.D() {
		return nil
	}
	return c.saveHead(now)
}

// saveHead кладёт последнюю принятую голову в журнал голов и в
// checkpoint.json.
func (c *Collector) saveHead(now time.Time) error {
	r := headRecord{ReceivedAt: c.wall().UTC(), Checkpoint: c.head}
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	err = c.persist("heads", func() error {
		if err := appendLine(filepath.Join(c.cfg.SpoolDir, headsFile), append(line, '\n')); err != nil {
			return err
		}
		return writeJSON(c.headPath(), r)
	})
	if err != nil {
		return err
	}
	c.headSaved = now
	return nil
}

// headConflict — голова, которая не продолжает принятую: улика в
// checkpoints-conflict.jsonl и ошибка в журнал, не чаще checkpoint_every.
func (c *Collector) headConflict(now time.Time, reason string, last, cp *proof.Checkpoint, consistency [][]byte) error {
	if !c.headAlarm.IsZero() && now.Sub(c.headAlarm) < c.cfg.CheckpointEvery.D() {
		return nil
	}
	c.log.Error("the store's chain does not extend the head this collector holds: the store rewrote or lost its history; both heads are signed by the store and kept as evidence, records keep being delivered",
		"reason", reason, "file", headConflictFile)
	line, err := json.Marshal(headConflict{ReceivedAt: c.wall().UTC(), Reason: reason, Previous: last, Checkpoint: cp, Consistency: consistency})
	if err != nil {
		return err
	}
	err = c.persist("conflict", func() error {
		return appendLine(filepath.Join(c.cfg.SpoolDir, headConflictFile), append(line, '\n'))
	})
	if err != nil {
		return errors.Join(errors.New("collector: the evidence of a rewritten chain is not on disk"), err)
	}
	c.headAlarm = now
	return nil
}

// headAlert — предупреждение о голове, не чаще checkpoint_every.
func (c *Collector) headAlert(now time.Time, msg string, args ...any) {
	if !c.headWarned.IsZero() && now.Sub(c.headWarned) < c.cfg.CheckpointEvery.D() {
		return
	}
	c.log.Warn(msg, args...)
	c.headWarned = now
}
