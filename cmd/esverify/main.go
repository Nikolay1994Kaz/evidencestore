// Command esverify — офлайн-проверка пакета доказательств по улике.
//
//	esverify -proof proof.json -store-key KEY -tsa-trust root.cer[,intermediate.cer] [-promise p.json]
//
// Проверяющему не нужен ни сервер хранилища, ни доверие к нему: только
// пакет, заранее закреплённый открытый ключ хранилища и сертификаты TSA (у
// НУЦ РК — root_rsa_2020.cer и nca_rsa_2022.cer).
//
// Код выхода: 0 — пакет проходит; 1 — не проходит (в том числе пакет не
// разбирается или обещание нарушено); 2 — неверный вызов или не читается
// файл ключа, сертификатов или обещания.
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
	"strings"

	"evidencestore/internal/gateway"
	"evidencestore/internal/proof"
	"evidencestore/internal/tsa"
	"evidencestore/internal/version"
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
	allowNoTSA := fs.Bool("allow-no-tsa", false, "accept a bundle without a TSA time-stamp after the record (then only the store's own signature vouches for it)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	showVersion := fs.Bool("version", false, "print the version and the commit it was built from")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: esverify -proof FILE -store-key KEY -tsa-trust CERT[,CERT] [-promise FILE] [-gateway-key KEY] [-allow-no-tsa] [-json]")
		fmt.Fprintln(stderr, "       esverify -version")
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "exit code: 0 the bundle verifies; 1 it does not (also an unparsable bundle or a broken promise); 2 bad usage or an unreadable key, certificate or promise file")
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
		raw := *gatewayKey
		if b, err := os.ReadFile(raw); err == nil {
			raw = string(b)
		}
		if pt.GatewayKey, err = gateway.ParseKey(raw); err != nil {
			return usageErr(err)
		}
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

	// Пакет, который не разбирается, — не неверный вызов, а провал проверки:
	// отчёт об этом печатается так же, в том числе в JSON.
	report := proof.Report{}
	bundle, err := proof.Parse(data)
	if err != nil {
		report.Checks = []proof.Check{{Name: "пакет разбирается", Detail: err.Error()}}
	} else {
		report = proof.Verify(bundle, pt)
		if promise != nil {
			// Обещание — часть вердикта: шапка отчёта не может говорить
			// «пройдена», когда обещание нарушено.
			perr := checkPromise(*promise, key, report, bundle)
			c := proof.Check{Name: "обещание при приёме выполнено: улика в цепи та же и вовремя", OK: perr == nil}
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
		enc.Encode(out)
	} else {
		fmt.Fprint(stdout, report.Text())
	}
	if !valid {
		return exitInvalid
	}
	return exitValid
}

func checkPromise(p proof.Promise, key ed25519.PublicKey, r proof.Report, b proof.Bundle) error {
	if err := proof.VerifyPromise(p, key); err != nil {
		return err
	}
	var linkTime int64
	for _, l := range b.Links {
		if l.Seq == r.LinkSeq {
			linkTime = l.UnixNano
		}
	}
	return proof.CheckPromise(p, r, linkTime)
}

func readKey(v string) (ed25519.PublicKey, error) {
	if data, err := os.ReadFile(v); err == nil {
		v = strings.TrimSpace(string(data))
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(v, "="))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("store key must be a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}
