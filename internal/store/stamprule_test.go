package store

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// stampRule — сверка обещания по меткам по всей цепи на диске (цепь
// свёрнута): перед листом записи нет листа токена со временем TSA позже
// времени приёма + MaxPromiseMMD, что бы ни стояло в сроке (Q-80). Сверка пакета версии 3
// (proof.CheckPromise) должна давать тот же ответ по одним листьям от головы
// под T1 до звена записи.
func stampRule(st *Store, p proof.Promise) error {
	_, chainDir, _ := dirs(st.cfg)
	limit := time.Unix(0, p.ReceivedAt+int64(proof.MaxPromiseMMD)).UTC()
	var worst time.Time
	var at uint64
	found := false
	stop := errors.New("stop")
	err := auditchain.ScanLeaves(chainDir, func(num uint64, l auditchain.Leaf) error {
		switch l.Type {
		case auditchain.EventTimestamp:
			if gen, err := tsa.GenTime(l.Payload); err == nil && gen.After(worst) {
				worst, at = gen, num
			}
		case auditchain.EventEvidence:
			if l.Scope == p.Source && l.Subject == strconv.FormatUint(p.Seq, 10) {
				found = true
				return stop
			}
		}
		return nil
	})
	switch {
	case err != nil && !errors.Is(err, stop):
		return err
	case !found:
		return fmt.Errorf("%s/%d is not in the chain", p.Source, p.Seq)
	case worst.After(limit):
		return fmt.Errorf("the token in leaf %d (TSA time %s) lies before the record, later than %s", at, worst.Format("15:04:05.000"), limit.Format("15:04:05.000"))
	}
	return nil
}

// checkBoth — сверка обещания по пакету версии 3 (её ответ) и та же сверка
// по всей цепи: ответы обязаны совпасть.
func checkBoth(t *testing.T, st *Store, p proof.Promise, r proof.Report, b proof.Bundle) error {
	t.Helper()
	if err := st.flush(); err != nil {
		t.Fatal(err)
	}
	bundle, chain := proof.CheckPromise(p, r, b, false), stampRule(st, p)
	if (bundle == nil) != (chain == nil) {
		t.Errorf("%s/%d: по пакету — %v, по всей цепи — %v", p.Source, p.Seq, bundle, chain)
	}
	return bundle
}
