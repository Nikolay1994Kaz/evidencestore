// Command esverify — офлайн-проверка пакета доказательств по улике.
//
//	esverify -proof proof.json -store-key KEY -tsa-trust root.cer[,intermediate.cer] [-promise p.json] [-heads DIR] [-body body.bin]
//
// Проверяющему не нужен ни сервер хранилища, ни доверие к нему: только
// пакет, заранее закреплённый открытый ключ хранилища и сертификаты TSA (у
// НУЦ РК — root_rsa_2020.cer и nca_rsa_2022.cer).
//
// -heads — каталог с подписанными головами, которые проверяющий сам взял у
// свидетеля (канал witness.url, газета, копия в чужом хранилище с
// блокировкой), все версии: цепь пакета обязана с ними сходиться. Рядом —
// список версий S3 (aws s3api list-object-versions) или журнал голов
// сборщика: тогда каждый свидетель закрепляет улику головой, которую получил
// первым (P-21, P-94).
//
// -body кладёт тело улики в файл байт в байт — только когда пакет прошёл
// все проверки: так из хранилища поднимают сам журнал, а отчёт показывает
// тело человеку с экранированными управляющими символами.
//
// Пакет за окно времени (evidencestore proof -from -to) распознаётся по
// полю "kind" и проверяется своими правилами (window.go): -from и -to —
// окно аудитора, -bodies DIR — тела в файлы.
//
// Код выхода: 0 — пакет проходит; 1 — не проходит (в том числе пакет не
// разбирается или обещание нарушено); 2 — неверный вызов, не читается
// файл ключа, сертификатов или обещания, каталог голов, или -body у пакета
// без ключа записи.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
	"github.com/Nikolay1994Kaz/evidencestore/internal/version"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const (
	exitValid   = 0
	exitInvalid = 1
	exitUsage   = 2
)

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("esverify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	proofPath := fs.String("proof", "", "proof bundle (JSON)")
	storeKey := fs.String("store-key", "", "pinned store public key (base64) or file containing it")
	tsaTrust := fs.String("tsa-trust", "", "TSA certificates, comma-separated (DER or PEM)")
	promisePath := fs.String("promise", "", "signed promise received by the collector (JSON), optional")
	gatewayKey := fs.String("gateway-key", "", "pinned gateway public key (64 hex) or file containing it: checks the gateway checkpoint signature yourself")
	headsDir := fs.String("heads", "", "directory with signed chain heads you took from a witness yourself, all versions (witness.url, a newspaper, someone else's locked copy): the chain in the bundle must agree with them; with the S3 versions list next to them (aws s3api list-object-versions > DIR/versions.json) or a collector's head journal, each witness fixes the record with the head it received first (give each collector a subdirectory of its own)")
	var witnessKeys []string
	fs.Func("witness-key", "verifier key of a C2SP witness (as eswitness vkey prints it) or a file containing it, taken from the witness's operator; repeat the flag for more witnesses: each must have cosigned a head at or after the record (for a bundle over a window, at or after its end), and the chain in the bundle must agree with it", func(v string) error {
		witnessKeys = append(witnessKeys, v)
		return nil
	})
	allowNoTSA := fs.Bool("allow-no-tsa", false, "accept a bundle without a TSA time-stamp after the record (then only the store's own signature vouches for it)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	bodyPath := fs.String("body", "", "once the bundle verifies, write the record body to FILE exactly as the source sent it (the bundle must carry the record key: evidencestore proof -dek)")
	showVersion := fs.Bool("version", false, "print the version and the commit it was built from")
	windowFrom := fs.String("from", "", "bundle over a window of time: the start of your window (RFC 3339); without -from and -to the window named in the bundle is used")
	windowTo := fs.String("to", "", "bundle over a window of time: the end of your window (RFC 3339)")
	bodiesDir := fs.String("bodies", "", "bundle over a window of time: once it verifies, write every opened body to DIR/<source>-<seq> exactly as the source sent it")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: esverify -proof FILE -store-key KEY -tsa-trust CERT[,CERT] [-promise FILE] [-gateway-key KEY] [-heads DIR] [-witness-key VKEY]… [-allow-no-tsa] [-json] [-body FILE]")
		fmt.Fprintln(stderr, "       esverify -proof WINDOW -store-key KEY -tsa-trust CERT[,CERT] [-from T -to T] [-heads DIR] [-witness-key VKEY]… [-json] [-bodies DIR]")
		fmt.Fprintln(stderr, "       (WINDOW: a bundle over a window of time, one source or every source: evidencestore proof -from -to)")
		fmt.Fprintln(stderr, "       esverify -version")
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "exit code: 0 the bundle verifies; 1 it does not (also an unparsable bundle or a broken promise); 2 bad usage, an unreadable key, certificate or promise file or heads directory, -body for a bundle without the record key, or -bodies for a bundle that opens no body though the window holds the records asked for (when it holds none — no records, none under the subject's label, or only months the bundle names no label for — it says so, and the code is 0)")
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *showVersion {
		fmt.Fprintln(stdout, version.String("esverify"))
		return exitValid
	}
	usageErr := func(err error) int {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}
	if *proofPath == "" || *storeKey == "" || *tsaTrust == "" {
		fs.Usage()
		return exitUsage
	}
	key, err := readKey(*storeKey)
	if err != nil {
		return usageErr(err)
	}
	trust, err := tsa.LoadTrust(*tsaTrust)
	if err != nil {
		return usageErr(err)
	}
	pt := proof.Trust{StoreKey: key, TSA: trust, AllowNoTSA: *allowNoTSA}
	if *gatewayKey != "" {
		// Сначала — как ключ: файл с именем, равным ключу, его не подменяет.
		if err := notAlsoFile("-gateway-key", *gatewayKey, func(v string) bool { _, err := gateway.ParseKey(v); return err == nil }); err != nil {
			return usageErr(err)
		}
		if pt.GatewayKey, err = gateway.ParseKey(*gatewayKey); err != nil {
			b, ferr := os.ReadFile(*gatewayKey)
			if ferr != nil {
				return usageErr(err)
			}
			if pt.GatewayKey, err = gateway.ParseKey(string(b)); err != nil {
				return usageErr(err)
			}
		}
	}
	if *headsDir != "" {
		if pt.Witness, err = readHeads(*headsDir); err != nil {
			return usageErr(fmt.Errorf("heads: %w", err))
		}
	}
	seenKey := map[string]string{}
	for _, raw := range witnessKeys {
		// Сначала — как ключ проверки: в нём всегда есть «/», и файл по пути,
		// равному настоящему ключу (подложенный в каталог аудитора), его не
		// подменяет. Не ключ — тогда путь к файлу с ключом.
		if err := notAlsoFile("-witness-key", raw, func(v string) bool { _, err := cosign.ParseVerifier(v); return err == nil }); err != nil {
			return usageErr(err)
		}
		v, err := cosign.ParseVerifier(raw)
		if err != nil {
			b, ferr := os.ReadFile(raw)
			if ferr != nil {
				return usageErr(fmt.Errorf("-witness-key: %w", err))
			}
			if v, err = cosign.ParseVerifier(strings.TrimSpace(string(b))); err != nil {
				return usageErr(fmt.Errorf("-witness-key %s: %w", raw, err))
			}
		}
		// Ключ хранилища свидетелем не бывает: его подписи держит
		// администратор хранилища, от которого свидетель и защищает (T).
		if v.Key.Equal(key) {
			return usageErr(fmt.Errorf("-witness-key %s: it is the store's own key (-store-key): a witness is someone else, out of the store administrator's reach", v.Name))
		}
		// Имя в подписи cosignature/v1 не подписано: один ключ под двумя
		// именами был бы двумя «свидетелями» с одной подписью.
		if name, ok := seenKey[string(v.Key)]; ok && name != v.Name {
			return usageErr(fmt.Errorf("-witness-key: one key is given as witness %s and as witness %s: it is one witness", name, v.Name))
		}
		seenKey[string(v.Key)] = v.Name
		pt.Cosigners = append(pt.Cosigners, v)
	}
	var promise *proof.Promise
	if *promisePath != "" {
		data, err := os.ReadFile(*promisePath)
		if err != nil {
			return usageErr(fmt.Errorf("promise file: %w", err))
		}
		promise = new(proof.Promise)
		if err := json.Unmarshal(data, promise); err != nil {
			return usageErr(fmt.Errorf("promise file %s: %w", *promisePath, err))
		}
	}
	data, err := os.ReadFile(*proofPath)
	if err != nil {
		return usageErr(err)
	}
	// Пакеты за окно — своими правилами; флаги пакета одной улики к ним не
	// подходят, и наоборот.
	if kind, _ := proof.BundleKind(data); kind == proof.WindowKind || kind == proof.SourceKind {
		var single []string
		for name, set := range map[string]bool{"-promise": *promisePath != "", "-gateway-key": *gatewayKey != "", "-allow-no-tsa": *allowNoTSA, "-body": *bodyPath != ""} {
			if set {
				single = append(single, name)
			}
		}
		return runWindow(data, kind, windowArgs{trust: pt, from: *windowFrom, to: *windowTo, bodies: *bodiesDir, asJSON: *asJSON, single: single}, stdout, stderr)
	}
	if *windowFrom != "" || *windowTo != "" || *bodiesDir != "" {
		return usageErr(errors.New("-from, -to and -bodies are for a bundle over a window of time (evidencestore proof -from -to)"))
	}

	// Пакет, который не разбирается, — не неверный вызов, а провал проверки:
	// отчёт об этом печатается так же, в том числе в JSON.
	report := proof.Report{}
	bundle, err := proof.Parse(data)
	if err != nil {
		report.Checks = []proof.Check{{Name: "the bundle parses", Detail: err.Error()}}
	} else {
		report = proof.Verify(bundle, pt)
		if promise != nil {
			// Обещание — часть вердикта: шапка отчёта не может говорить
			// «пройдена», когда обещание нарушено.
			perr := checkPromise(*promise, key, report, bundle, *allowNoTSA)
			c := proof.Check{Name: "the promise given at intake is kept: the same record, in the chain in time", OK: perr == nil}
			if perr != nil {
				c.Detail = perr.Error()
			}
			report.Checks = append(report.Checks, c)
		}
	}
	valid := report.Valid()

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", " ")
		out := map[string]any{"valid": valid, "checks": report.Checks, "notes": report.Notes(),
			"source": report.Header.Source, "seq": report.Header.Seq, "received_at": report.Header.ReceivedAt,
			"lower": report.Lower, "upper": report.Upper, "body_opened": report.BodyOpened}
		if report.Gateway != nil {
			out["gateway"] = report.Gateway
			out["gateway_checkpoint"] = report.GatewayCheckpoint
		}
		if report.WitnessChecked {
			out["witness_head"] = report.WitnessHead
			out["witness_fork"] = report.WitnessFork
			out["witness_refused"] = report.WitnessRefused
			out["witness_received"] = witnessReceived(report.WitnessReceived)
		}
		if report.CosignChecked {
			out["cosigned"] = report.Cosigned
		}
		enc.Encode(out)
	} else {
		fmt.Fprint(stdout, report.Text())
	}
	if !valid {
		if *bodyPath != "" {
			fmt.Fprintln(stderr, "body not written: the bundle does not verify")
		}
		return exitInvalid
	}
	if *bodyPath != "" {
		// Тело выдаётся только из пакета, прошедшего все проверки, и байт в
		// байт: Text экранирует управляющие символы, а журнал поднимают
		// ровно из тех байтов, что прислал источник.
		if !report.BodyOpened {
			fmt.Fprintln(stderr, "error: -body: the bundle carries no record key, and there is no body to write: it was asked without -dek (then request it with evidencestore proof -dek), the month key is destroyed or awaits destruction, the key was removed from this bundle, or the store held it back")
			return exitUsage
		}
		// Тело — содержимое улики: файл только владельцу.
		if err := os.WriteFile(*bodyPath, report.Body, 0o600); err != nil {
			return usageErr(fmt.Errorf("-body: %w", err))
		}
		fmt.Fprintf(stderr, "body written to %s (%d bytes)\n", *bodyPath, len(report.Body))
	}
	return exitValid
}

func checkPromise(p proof.Promise, key ed25519.PublicKey, r proof.Report, b proof.Bundle, allowNoTSA bool) error {
	if err := proof.VerifyPromise(p, key); err != nil {
		return err
	}
	return proof.CheckPromise(p, r, b, allowNoTSA)
}

// readHeads читает головы, которые проверяющий сам взял у свидетеля: каждый
// файл каталога, в том числе во вложенных (версии объектов, поколения копии,
// файлы голов сборщиков — proof.ParseHeads). Что не разбирается как голова,
// остаётся в списке пустой головой: сверка его не засчитает, а отчёт
// назовёт, сколько таких.
func readHeads(dir string) (*proof.Witness, error) {
	w := &proof.Witness{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, _ := filepath.Rel(dir, path)
		w.AddFile(name, data)
		return nil
	})
	return w, err
}

// readKey — ключ хранилища: сначала как ключ (файл с именем, равным ключу,
// его не подменяет), иначе — файл с ключом.
func readKey(v string) (ed25519.PublicKey, error) {
	if err := notAlsoFile("-store-key", v, func(v string) bool { _, ok := parseStoreKey(v); return ok }); err != nil {
		return nil, err
	}
	if key, ok := parseStoreKey(v); ok {
		return key, nil
	}
	if data, err := os.ReadFile(v); err == nil {
		if key, ok := parseStoreKey(strings.TrimSpace(string(data))); ok {
			return key, nil
		}
	}
	return nil, errors.New("store key must be a base64 Ed25519 public key")
}

// notAlsoFile — значение флага разбирается как ключ и при этом есть файл с
// таким путём: какой из двух имел в виду аудитор, не угадать (путь из 43
// знаков base64 разбирается как ключ хранилища) — неверный вызов.
func notAlsoFile(flag, v string, isKey func(string) bool) error {
	if !isKey(v) {
		return nil
	}
	if _, err := os.Stat(v); err == nil {
		return fmt.Errorf("%s %q is both a key and the name of a file: pass the key itself, or the file as ./%s", flag, v, v)
	}
	return nil
}

func parseStoreKey(v string) (ed25519.PublicKey, bool) {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(v, "="))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}
