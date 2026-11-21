package collector

// Вход не из файлов (internal/input): как сборщик его заводит, что кладёт от
// него в буфер и что помнит.
//
// В буфере у такого входа те же записи, что у файлов, только на месте пары
// «inode, смещение» лежит место входа (cursor): вид 'L' — запись входа и место
// после неё; вид 'P' — пропуск: вход потерял данные, номер пропущен. Вида 'D'
// у входа нет. Снимок места — input.json: он пишется раньше, чем доставленное
// уходит из буфера, как files.json у файлов, и по нему же видно, чей это
// буфер.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/input"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pginput"
)

// newInput заводит вход по настройкам; nil — читаются файлы. Новый вид
// источника добавляется сюда.
func newInput(cfg *Config, log *slog.Logger) (input.Input, error) {
	switch {
	case cfg.in != nil:
		return cfg.in, nil
	case cfg.Postgres != nil:
		return pginput.New(*cfg.Postgres, log)
	}
	return nil, nil
}

// inputState — input.json. Started — запись «старт» уже лежит в буфере: первый
// запуск пишет input.json дважды, до неё (false) и после (true). Пустой буфер
// при started — буфер потерян; при !started — первый запуск упал посередине и
// просто повторяется (у файлов эту пару играют start-files.json и files.json).
type inputState struct {
	Cursor  uint64 `json:"cursor"`
	Started bool   `json:"started"`
}

func (c *Collector) saveInput(started bool) error {
	return c.persist("input", func() error {
		return writeJSON(c.inputPath(), inputState{Cursor: c.cursor, Started: started})
	})
}

// savePositions — снимок того, докуда прочитан вход: реестр файлов или место
// входа.
func (c *Collector) savePositions() error {
	if c.input != nil {
		return c.saveInput(true)
	}
	return c.saveFiles()
}

// replayInput — запись буфера при запуске, когда вход не файлы.
func (c *Collector) replayInput(p uint64, r spoolRecord, started *bool) error {
	switch r.kind {
	case kindStart:
		*started = true
		c.acked = max(c.acked, r.seq)
	case kindLine, kindPos:
		c.cursor = uint64(r.pos.Offset)
	default:
		return fmt.Errorf("collector spool position %d: record %q in the spool of an input that is not files", p, r.kind)
	}
	return nil
}

// ReadAll — для -once: всё, что было у источника к моменту вызова. У файлов
// это обычный проход.
func (c *Collector) ReadAll(ctx context.Context) (int, error) {
	if c.input != nil {
		return c.input.ReadAll(ctx)
	}
	return c.ReadOnce()
}

// sink — буфер сборщика глазами входа (input.Sink).
type sink struct{ c *Collector }

func (s sink) Next() uint64 { return s.c.nextSeq }

func (s sink) Emit(bodies [][]byte, cursor uint64) (uint64, error) {
	c := s.c
	if len(bodies) == 0 {
		return 0, errors.New("collector: an input emitted nothing")
	}
	first := c.nextSeq
	recs := make([]spoolRecord, len(bodies))
	for i, b := range bodies {
		if len(b) > evidence.MaxBodyLen {
			return 0, fmt.Errorf("collector: an input emitted a record of %d bytes: the store takes %d at most", len(b), evidence.MaxBodyLen)
		}
		// Место сдвигает только последняя запись пачки: пачка может лечь на
		// диск не вся, и тогда вход должен получить её заново.
		at := c.cursor
		if i == len(bodies)-1 {
			at = cursor
		}
		recs[i] = spoolRecord{kind: kindLine, seq: first + uint64(i), pos: filePos{Offset: int64(at)}, body: b}
	}
	if err := c.appendSpool(recs); err != nil {
		return 0, err
	}
	c.nextSeq += uint64(len(recs))
	c.pending += len(recs)
	c.cursor = cursor
	return first, nil
}

func (s sink) Gap(why string) error {
	c := s.c
	c.log.Error(why + "; leaving a gap in numbering")
	c.nextSeq++
	if err := c.appendSpool([]spoolRecord{{kind: kindPos, seq: c.nextSeq - 1, pos: filePos{Offset: int64(c.cursor)}}}); err != nil {
		// Записи нет — нет и пропуска: номер назад, как в forget.
		c.nextSeq--
		return err
	}
	return nil
}

// Source — имя источника: CommonName сертификата сборщика.
func (c *Collector) Source() string { return c.source }

// SetLogger меняет журнал сборщика — до Run: когда один процесс ведёт
// несколько источников, у каждого в строках журнала своё имя.
func (c *Collector) SetLogger(log *slog.Logger) {
	c.log = log
	if l, ok := c.input.(interface{ SetLogger(*slog.Logger) }); ok {
		l.SetLogger(log)
	}
}
