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

// Пакет за окно времени (DECISIONS, п. 27): проверка, отчёт, тела в файлы.

// windowArgs — что из вызова нужно проверке окна. single — заданные флаги
// пакета одной улики: для окна это неверный вызов.
type windowArgs struct {
	trust    proof.Trust
	from, to string
	bodies   string
	asJSON   bool
	single   []string
}

func runWindow(data []byte, a windowArgs, stdout, stderr io.Writer) int {
	usageErr := func(err error) int {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}
	if len(a.single) > 0 {
		sort.Strings(a.single)
		return usageErr(fmt.Errorf("%s: not for a window bundle", strings.Join(a.single, ", ")))
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

	// Пакет, который не разбирается, — провал проверки, как у пакета одной
	// улики.
	var win proof.WindowReport
	b, err := proof.ParseWindow(data)
	if err != nil {
		win.Checks = []proof.Check{{Name: "the window bundle parses", Detail: err.Error()}}
	} else {
		win = proof.VerifyWindow(b, a.trust, from, to)
	}
	valid := win.Valid()

	if a.asJSON {
		out := map[string]any{"valid": valid, "kind": proof.WindowKind, "checks": win.Checks, "notes": win.Notes(),
			"from": win.From, "to": win.To, "window_from_bundle": win.FromBundle,
			"lower": win.Lower, "upper": win.Upper, "from_start": win.FromStart,
			"lower_head": win.LowerHead, "stretch_end": win.StretchEnd, "head": win.HeadSeq, "leaves": win.Leaves,
			"sources": win.Sources, "records_attached": win.Attached, "bodies_opened": len(win.Bodies)}
		if win.WitnessChecked {
			out["witness_head"] = win.WitnessHead
			out["witness_fork"] = win.WitnessFork
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", " ")
		enc.Encode(out)
	} else {
		fmt.Fprint(stdout, win.Text())
	}
	if !valid {
		if a.bodies != "" {
			fmt.Fprintln(stderr, "bodies not written: the bundle does not verify")
		}
		return exitInvalid
	}
	if a.bodies != "" {
		if len(win.Bodies) == 0 {
			fmt.Fprintln(stderr, "error: -bodies: the bundle carries no record keys (request them with evidencestore proof -from -to -source S -dek), or the month keys were destroyed: there are no bodies to write")
			return exitUsage
		}
		if err := writeBodies(a.bodies, win.Bodies); err != nil {
			return usageErr(fmt.Errorf("-bodies: %w", err))
		}
		// Сообщение — в stderr: -json остаётся чистым JSON.
		fmt.Fprintf(stderr, "%d bodies written to %s\n", len(win.Bodies), a.bodies)
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
