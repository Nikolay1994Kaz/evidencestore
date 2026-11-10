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
	// warn — что -bodies не записал и почему, при коде 0: месяцы окна, где не
	// открыто ни одно тело субъекта (P-75), месяцы-листья (T-05), улики без
	// ключа (T-03).
	warn []string
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
		out["witness_received"] = witnessReceived(win.WitnessReceived)
	}
	if win.CosignChecked {
		out["cosigned"] = win.Cosigned
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
	noBodies := "the bundle opens no bodies in the window: it carries no record keys (request them with evidencestore proof -window -source S -dek), the source it was taken for has no records in the window, or " + proof.KeylessReasons + ": there are no bodies to write"
	if b.KeysFor != "" {
		// Ключи уже просили: совет взять -dek вёл бы по кругу (E4-08). Пометка
		// не подписана, и записи её источника в окне отчёт считает сам.
		quiet := true
		for _, s := range win.Sources {
			if s.Name == b.KeysFor && s.InWindow > 0 {
				quiet = false
			}
		}
		noBodies = fmt.Sprintf("the bundle opens no bodies in the window: it says it carries the keys of %q, and that source has no records received in the window: there are no bodies to write", b.KeysFor)
		if !quiet {
			noBodies = fmt.Sprintf("the bundle opens no bodies in the window: it says it carries the keys of %q, and the records of that source in the window come without them: %s; there are no bodies to write", b.KeysFor, proof.KeylessReasons)
		}
	}
	var warn []string
	if win.LeafOnly > 0 {
		noBodies = leafOnlyNoBodies(win.LeafOnlyMonths)
		warn = append(warn, leafOnlyWarn(win.LeafOnlyMonths))
	}
	if k := win.Keyless(); k > 0 {
		warn = append(warn, keylessWarn(k))
	}
	out["leaf_only"], out["leaf_only_months"], out["key_receipts"] = win.LeafOnly, win.LeafOnlyMonths, win.KeyReceipts
	return windowResult{valid: win.Valid(), text: win.Text(), json: out, bodies: win.Bodies, nothing: nothing, noBodies: noBodies, warn: warn}
}

// witnessReceived — время получения закрепляющей головы для -json: null, если
// времени у голов нет (закрепила первая по номеру, P-21).
func witnessReceived(at time.Time) any {
	if at.IsZero() {
		return nil
	}
	return at
}

// leafOnlyWarn — что -bodies не записал, когда часть тел записана, а месяцы
// пришли листом (P-81, E1-02, T-05).
func leafOnlyWarn(months []string) string {
	return fmt.Sprintf("the bundle carries no evidence for %s: their records are not among the bodies written (the report says why)", proof.QuotedList(months))
}

// keylessWarn — улики окна без ключа записи: их тел среди записанных нет
// (T-03).
func keylessWarn(n int) string {
	return fmt.Sprintf("%d records of the window come with their evidence and without their record key, and their bodies are not among those written: %s", n, proof.KeylessReasons)
}

// leafOnlyNoBodies — почему -bodies нечего писать, когда записи окна пришли
// листом: их месяц пакет отдал без улик (P-80).
func leafOnlyNoBodies(months []string) string {
	return fmt.Sprintf("the records of the window lie in months the bundle carries no evidence for (%s), and there are no bodies to write: the store sends a month whose key is destroyed or awaits destruction that way, but anyone can take a month's evidence out of a bundle, and the with_keys and keys_for marks are not signed; %s", proof.QuotedList(months), proof.ReceiptsPath)
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
	noBodies := "the bundle opens no bodies in the window: it carries no record keys (request them with evidencestore proof -source S -dek), or " + proof.KeylessReasons + ": there are no bodies to write"
	var warn []string
	if src.LeafOnly > 0 && src.Subject == "" {
		noBodies = leafOnlyNoBodies(src.LeafOnlyMonths)
		warn = append(warn, leafOnlyWarn(src.LeafOnlyMonths))
	}
	if k := src.Keyless(); k > 0 && src.Subject == "" {
		warn = append(warn, keylessWarn(k))
	}
	out["leaf_only"], out["leaf_only_months"] = src.LeafOnly, src.LeafOnlyMonths
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
		noBodies = "the records under this label in the window come without record keys: " + proof.KeylessUnderLabel + "; ask its operator"
		// Под метками записей нет — это «под меткой пусто», а не ошибка: код 0,
		// скрипт идёт по окнам дальше (закон -bodies, DECISIONS, п. 32). Фраза
		// не говорит «записей нет»: без открытого тела метка ни к кому не
		// привязана, записи клиента могут лежать без метки, а месяцу без метки
		// (ключ уничтожен или ждёт уничтожения, а может, метку сняли) пакет не
		// показывает ничьих записей вовсе.
		if src.UnderLabels() == 0 && src.InWindow > 0 {
			// Каждый месяц окна без открытого тела — по имени (P-75, E2-02), и
			// отдельно те, которым пакет не называет метки.
			nothing = fmt.Sprintf("no bodies to write: no record of the window is under this label, and no body of %q is open in %s, which does not show that the subject has none there: the report says why", src.Subject, proof.QuotedList(src.SubjectUnconfirmedMonths))
			if src.SubjectNoLabel > 0 {
				nothing += fmt.Sprintf(" (the bundle names no label for %s)", proof.QuotedList(src.SubjectNoLabelMonths))
			}
		}
		// Одна разбивка с отчётом: records + unbound + others_closed = records_in_window.
		out["subject"] = map[string]any{"field": src.SubjectField, "value": src.Subject, "label": src.SubjectLabel,
			"records": src.SubjectRecords, "opened": src.SubjectOpened, "keyless": src.SubjectKeyless,
			"unbound": src.SubjectUnbound, "unbound_months": src.SubjectUnboundMonths,
			"others_closed": src.ClosedOthers(), "others": src.SubjectOthers, "unlabeled": src.SubjectUnlabeled,
			"no_label": src.SubjectNoLabel, "no_label_months": src.SubjectNoLabelMonths,
			"unconfirmed_months": src.SubjectUnconfirmedMonths}
		if len(src.SubjectUnconfirmedMonths) > 0 {
			warn = append(warn, fmt.Sprintf("no body of %q is open in %s: its records there, if any, are not among the bodies written (the report says why)", src.Subject, proof.QuotedList(src.SubjectUnconfirmedMonths)))
		}
		if src.SubjectKeyless > 0 {
			warn = append(warn, fmt.Sprintf("%d records under this label come without their record key, and their bodies are not among those written: %s", src.SubjectKeyless, proof.KeylessUnderLabel))
		}
	}
	if src.WitnessChecked {
		out["witness_head"] = src.WitnessHead
		out["witness_fork"] = src.WitnessFork
		out["witness_refused"] = src.WitnessRefused
		out["witness_received"] = witnessReceived(src.WitnessReceived)
	}
	if src.CosignChecked {
		out["cosigned"] = src.Cosigned
	}
	return windowResult{valid: src.Valid(), text: src.Text(), json: out, bodies: src.Bodies, noBodies: noBodies, nothing: nothing, warn: warn}
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
		for _, w := range res.warn {
			fmt.Fprintln(stderr, w)
		}
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
