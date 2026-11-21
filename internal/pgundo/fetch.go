package pgundo

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
)

// Fetcher — как достать из хранилища записи транзакции и проверить их: один
// раздел настроек у оператора (esundo -config) и у MCP-сервера (esmcp, "undo").
// Команды — списком аргументов, без оболочки.
type Fetcher struct {
	// Index — справочник сборщика (index.jsonl источника "postgres"): под
	// какими номерами записей источника лежит транзакция.
	Index string `json:"index"`
	// Proof — команда выдачи пакета одной записи; к ней дописывается
	// "-seq N -out FILE": ["evidencestore", "proof", "-config", "…", "-source", "pg-agent", "-dek"].
	Proof []string `json:"proof"`
	// Verify — команда проверки; к ней дописывается "-proof FILE -body FILE":
	// ["esverify", "-store-key", "…", "-tsa-trust", "…"]. Тело берётся, только
	// если проверка прошла (код выхода 0): ключ хранилища и доверие к меткам
	// времени заданы здесь, а не тем, кто выдал пакет.
	Verify []string `json:"verify"`
	// Stamp — команда, которую звать перед выдачей пакетов, чтобы свежая запись
	// получила метку времени: ["evidencestore", "stamp", "-config", "…"]. Необязательна.
	Stamp []string `json:"stamp"`
	// Wait — сколько ждать, пока сборщик прочитает транзакцию, а запись дойдёт
	// до хранилища. По умолчанию 15s.
	Wait config.Duration `json:"wait"`
}

// Validate проверяет раздел и ставит умолчания; относительный путь
// справочника — от base.
func (f *Fetcher) Validate(base string) error {
	if f.Index == "" || len(f.Proof) == 0 || len(f.Verify) == 0 {
		return errors.New("index, proof and verify are all required")
	}
	if !filepath.IsAbs(f.Index) {
		f.Index = filepath.Join(base, f.Index)
	}
	if f.Wait == 0 {
		f.Wait = config.Duration(15 * time.Second)
	}
	if f.Wait < 0 {
		return errors.New("wait is negative")
	}
	return nil
}

// Fetch достаёт из хранилища записи транзакции xid: по справочнику сборщика
// узнаёт их номера, на каждую берёт пакет и отдаёт его команде проверки.
// Транзакция, которую сборщик ещё не прочитал, и запись, которая до хранилища
// ещё не дошла, ждут до Wait.
func (f *Fetcher) Fetch(xid uint32) ([][]byte, error) {
	deadline := time.Now().Add(f.Wait.D())
	var entry pgtap.IndexEntry
	for {
		// После пересылки транзакция лежит в справочнике дважды: Lookup отдаёт
		// последнюю строку.
		e, found, err := pgtap.Lookup(f.Index, xid)
		if err != nil {
			return nil, err
		}
		if found {
			entry = e
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("transaction %d is not in the collector's index: it changed no watched table, or the collector has not read it yet", xid)
		}
		time.Sleep(100 * time.Millisecond)
	}
	dir, err := os.MkdirTemp("", "esundo-fetch-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	run := func(argv []string, extra ...string) error {
		out, err := exec.Command(argv[0], append(slices.Clone(argv[1:]), extra...)...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %w: %s", filepath.Base(argv[0]), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	var lines [][]byte
	for seq := entry.FirstSeq; seq <= entry.LastSeq; seq++ {
		bundle := filepath.Join(dir, fmt.Sprintf("%d.json", seq))
		body := filepath.Join(dir, fmt.Sprintf("%d.body", seq))
		for {
			if len(f.Stamp) > 0 {
				run(f.Stamp)
			}
			err := run(f.Proof, "-seq", strconv.FormatUint(seq, 10), "-out", bundle)
			if err == nil {
				// Пакет без метки времени после записи проверку не проходит: тогда — ещё попытка.
				err = run(f.Verify, "-proof", bundle, "-body", body)
			}
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("record %d: %w", seq, err)
			}
			time.Sleep(300 * time.Millisecond)
		}
		line, err := os.ReadFile(body)
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}
	return lines, nil
}
