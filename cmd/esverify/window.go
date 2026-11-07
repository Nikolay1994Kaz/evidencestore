package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Пакеты за окно времени — все источники (DECISIONS, п. 27) и один
// источник (п. 28): проверка, отчёт, тела в файлы.

// windowArgs — что из вызова нужно проверке окна. single — заданные флаги
// пакета одной улики: для окна это неверный вызов.
type windowArgs struct {
	trust    proof.Trust
	from, to string
	bodies   string
	asJSON   bool
	single   []string
}

// windowResult — итог проверки пакета за окно любого вида: отчёт текстом и
// JSON, тела для -bodies.
type windowResult struct {
	valid  bool
	text   string
	json   map[string]any
	bodies []proof.WindowBody
	// noBodies — почему -bodies нечего писать, когда записи окна закрыты: код 2.
	noBodies string
	// nothing — в окне нет того, о чём просили: это ответ, а не ошибка (код 0),
	// и скрипт, идущий окно за окном, не встаёт. Пусто — такого не доказано.
	nothing string
}

// noRecords — в окне нет записей. Говорит только о том, что показывает пакет: окно
// из пакета ничем не подписано, а номера, потерянные на окне, выглядят так же.
func noRecords(fromBundle bool) string {
	if fromBundle {
		return "no bodies to write: the bundle shows no record received in the window it names"
	}
	return "no bodies to write: the bundle shows no record received in your window"
}

// verifyWindow — пакет за окно по всем источникам. Пакет, который не
// разбирается, — провал проверки, как у пакета одной улики.
func verifyWindow(data []byte, trust proof.Trust, from, to time.Time) windowResult {
	var win proof.WindowReport
	b, err := proof.ParseWindow(data)
	if err != nil {
		win.Checks = []proof.Check{{Name: "the window bundle parses", Detail: err.Error()}}
	} else {
		win = proof.VerifyWindow(b, trust, from, to)
	}
	out := map[string]any{"valid": win.Valid(), "kind": proof.WindowKind, "checks": win.Checks, "notes": win.Notes(),
		"from": win.From, "to": win.To, "window_from_bundle": win.FromBundle,
		"lower": win.Lower, "upper": win.Upper, "from_start": win.FromStart,
		"lower_head": win.LowerHead, "stretch_end": win.StretchEnd, "head": win.HeadSeq, "leaves": win.Leaves,
		"sources": win.Sources, "records_attached": win.Attached, "bodies_opened": len(win.Bodies)}
	if win.WitnessChecked {
		out["witness_head"] = win.WitnessHead
		out["witness_fork"] = win.WitnessFork
		out["witness_refused"] = win.WitnessRefused
	}
	// Пакет -window не называет источник, тела которого несёт: что окно пусто,
	// видно, только если в нём нет записей ни одного источника.
	inWindow := 0
	for _, s := range win.Sources {
		inWindow += s.InWindow
	}
	var nothing string
	if inWindow == 0 {
		nothing = noRecords(win.FromBundle)
	}
	return windowResult{valid: win.Valid(), text: win.Text(), json: out, bodies: win.Bodies, nothing: nothing,
		noBodies: "the bundle opens no bodies in the window: it carries no record keys (request them with evidencestore proof -source S -dek), the source it was taken for has no records in the window, or the month keys were destroyed: there are no bodies to write"}
}

// verifySource — пакет по одному источнику.
func verifySource(data []byte, trust proof.Trust, from, to time.Time) windowResult {
	var src proof.SourceReport
	b, err := proof.ParseSource(data)
	if err != nil {
		src.Checks = []proof.Check{{Name: "the source bundle parses", Detail: err.Error()}}
	} else {
		src = proof.VerifySource(b, trust, from, to)
	}
	out := map[string]any{"valid": src.Valid(), "kind": proof.SourceKind, "checks": src.Checks, "notes": src.Notes(),
		"source": src.Source, "source_named": src.SourceNamed, "from": src.From, "to": src.To, "window_from_bundle": src.FromBundle,
		"lower": src.Lower, "upper": src.Upper, "from_start": src.FromStart,
		"lower_head": src.LowerHead, "upper_head": src.UpperHead, "head": src.HeadSeq,
		"records": src.Records, "records_in_window": src.InWindow, "first_seq": src.FirstSeq, "last_seq": src.LastSeq,
		"holes": src.Holes, "records_attached": src.Attached, "bodies_opened": len(src.Bodies),
		"gateway_records": src.GatewayRecords, "gateway_broken": src.GatewayBroken}
	noBodies := "the bundle opens no bodies in the window: it carries no record keys (request them with evidencestore proof -source S -dek), or the month keys were destroyed: there are no bodies to write"
	if src.Withheld() > 0 {
		noBodies = "the bundle opens no bodies in the window: the store found its records broken at intake, and their bodies are not opened here: single-record bundles show what is wrong"
	}
	var nothing string
	if src.InWindow == 0 {
		nothing = noRecords(src.FromBundle)
	}
	if src.Subject != "" {
		// Не «попросите -dek»: это открыло бы всех клиентов окна. Сюда доходят
		// записи под меткой без ключей: записей нет — это nothing.
		noBodies = "the records under this label in the window come without record keys: the keys were removed from this bundle, the month key was destroyed (retention) or awaits destruction, or the store held it back; ask its operator"
		// Не «записей нет»: без открытого тела метка ни к кому не привязана, а
		// записи клиента могут лежать без метки.
		if src.SubjectRecords == 0 && src.InWindow > 0 {
			nothing = "no bodies to write: no record of the window is under this label, which does not show that the subject has none: the report says why"
		}
		out["subject"] = map[string]any{"field": src.SubjectField, "value": src.Subject, "label": src.SubjectLabel, "records": src.SubjectRecords,
			"opened": src.SubjectOpened, "keyless": src.SubjectKeyless, "others": src.SubjectOthers, "unlabeled": src.SubjectUnlabeled}
	}
	if src.WitnessChecked {
		out["witness_head"] = src.WitnessHead
		out["witness_fork"] = src.WitnessFork
		out["witness_refused"] = src.WitnessRefused
	}
	return windowResult{valid: src.Valid(), text: src.Text(), json: out, bodies: src.Bodies, noBodies: noBodies, nothing: nothing}
}

func runWindow(data []byte, kind string, a windowArgs, stdout, stderr io.Writer) int {
	usageErr := func(err error) int {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}
	if len(a.single) > 0 {
		sort.Strings(a.single)
		return usageErr(fmt.Errorf("%s: not for a bundle over a window of time", strings.Join(a.single, ", ")))
	}
	var from, to time.Time
	if a.from != "" || a.to != "" {
		var err error
		if from, err = time.Parse(time.RFC3339Nano, a.from); err != nil {
			return usageErr(fmt.Errorf("-from: %w", err))
		}
		if to, err = time.Parse(time.RFC3339Nano, a.to); err != nil {
			return usageErr(fmt.Errorf("-to: %w", err))
		}
	}

	verify := verifyWindow
	if kind == proof.SourceKind {
		verify = verifySource
	}
	res := verify(data, a.trust, from, to)
	valid := res.valid

	if a.asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", " ")
		enc.Encode(res.json)
	} else {
		fmt.Fprint(stdout, res.text)
	}
	if !valid {
		if a.bodies != "" {
			fmt.Fprintln(stderr, "bodies not written: the bundle does not verify")
		}
		return exitInvalid
	}
	if a.bodies != "" {
		if len(res.bodies) == 0 && res.nothing != "" {
			fmt.Fprintln(stderr, res.nothing)
			return exitValid
		}
		if len(res.bodies) == 0 {
			fmt.Fprintln(stderr, "error: -bodies:", res.noBodies)
			return exitUsage
		}
		if err := writeBodies(a.bodies, res.bodies); err != nil {
			return usageErr(fmt.Errorf("-bodies: %w", err))
		}
		// Сообщение — в stderr: -json остаётся чистым JSON.
		fmt.Fprintf(stderr, "%d bodies written to %s\n", len(res.bodies), a.bodies)
	}
	return exitValid
}

// writeBodies пишет тела байт в байт, каждое в файл <источник>-<номер>,
// только владельцу, как -body. Имя источника пришло из пакета: всё, кроме
// букв, цифр, точки, дефиса и подчёркивания, заменяется на «_», чтобы имя не
// вывело файл из каталога.
func writeBodies(dir string, bodies []proof.WindowBody) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	names := map[string]bool{}
	for _, b := range bodies {
		name := fmt.Sprintf("%s-%d", safeName(b.Source), b.Seq)
		if names[name] {
			return errors.New("two bodies map to file " + name + ": source names differ only in characters that are not kept")
		}
		names[name] = true
		if err := os.WriteFile(filepath.Join(dir, name), b.Body, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func safeName(s string) string {
	return strings.Map(func(c rune) rune {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
			return c
		}
		return '_'
	}, s)
}
