// Command esverify — офлайн-проверка пакета доказательств по улике.
//
//	esverify -proof proof.json -store-key KEY -tsa-trust root.cer[,intermediate.cer] [-promise p.json]
//
// Проверяющему не нужен ни сервер хранилища, ни доверие к нему: только
// пакет, заранее закреплённый открытый ключ хранилища и сертификаты TSA (у
// НУЦ РК — root_rsa_2020.cer и nca_rsa_2022.cer). Код выхода: 0 — пакет
// проходит, 1 — нет, 2 — неверный вызов.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"evidencestore/internal/gateway"
	"evidencestore/internal/proof"
	"evidencestore/internal/tsa"
)

func main() {
	proofPath := flag.String("proof", "", "proof bundle (JSON)")
	storeKey := flag.String("store-key", "", "pinned store public key (base64) or file containing it")
	tsaTrust := flag.String("tsa-trust", "", "TSA certificates, comma-separated (DER or PEM)")
	promisePath := flag.String("promise", "", "signed promise received by the collector (JSON), optional")
	gatewayKey := flag.String("gateway-key", "", "pinned gateway public key (64 hex) or file containing it: checks the gateway checkpoint signature yourself")
	asJSON := flag.Bool("json", false, "print the report as JSON")
	flag.Parse()
	if *proofPath == "" || *storeKey == "" || *tsaTrust == "" {
		fmt.Fprintln(os.Stderr, "usage: esverify -proof FILE -store-key KEY -tsa-trust CERT[,CERT] [-promise FILE] [-gateway-key KEY]")
		os.Exit(2)
	}
	data, err := os.ReadFile(*proofPath)
	fail(err)
	bundle, err := proof.Parse(data)
	fail(err)
	key, err := readKey(*storeKey)
	fail(err)
	trust, err := tsa.LoadTrust(*tsaTrust)
	fail(err)

	pt := proof.Trust{StoreKey: key, TSA: trust}
	if *gatewayKey != "" {
		raw := *gatewayKey
		if b, err := os.ReadFile(raw); err == nil {
			raw = string(b)
		}
		pt.GatewayKey, err = gateway.ParseKey(raw)
		fail(err)
	}
	report := proof.Verify(bundle, pt)
	valid := report.Valid()
	var promiseErr error
	if *promisePath != "" {
		promiseErr = checkPromise(*promisePath, key, report, bundle)
		valid = valid && promiseErr == nil
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", " ")
		out := map[string]any{"valid": valid, "checks": report.Checks, "notes": report.Notes(),
			"source": report.Header.Source, "seq": report.Header.Seq, "received_at": report.Header.ReceivedAt,
			"lower": report.Lower, "upper": report.Upper, "body_opened": report.BodyOpened}
		if report.Gateway != nil {
			out["gateway"] = report.Gateway
			out["gateway_checkpoint"] = report.GatewayCheckpoint
		}
		if promiseErr != nil {
			out["promise_error"] = promiseErr.Error()
		}
		enc.Encode(out)
	} else {
		fmt.Print(report.Text())
		if *promisePath != "" {
			if promiseErr != nil {
				fmt.Printf("\n✘ обещание при приёме нарушено: %v\n", promiseErr)
			} else {
				fmt.Println("\n✔ обещание при приёме выполнено: улика в цепи та же и вовремя")
			}
		}
	}
	if !valid {
		os.Exit(1)
	}
}

func checkPromise(path string, key ed25519.PublicKey, r proof.Report, b proof.Bundle) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var p proof.Promise
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
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
		return nil, fmt.Errorf("store key must be a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}
