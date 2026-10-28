package store

import (
	"strconv"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// Q-84: форма цепи, которую обещает README, сверенная по самой цепи. После
// пересмотра обещание сверяется по меткам, а не по времени звеньев, и
// механизмы шкалы и звеньев (догон по тику, токен в своём звене, шкала по
// монотонным часам) больше его не держат: тесты, которые ловили их поломку
// через сверку обещания, её больше не видят (мутации X30, X41, X43, X44, X45
// выжили).

// chainLink — звено цепи на диске с его листьями.
type chainLink struct {
	seq    uint64
	at     int64
	leaves []auditchain.Leaf
}

func chainLinks(t *testing.T, st *Store) []chainLink {
	t.Helper()
	if err := st.flush(); err != nil {
		t.Fatal(err)
	}
	_, chainDir, _ := dirs(st.cfg)
	links, err := auditchain.ReadChain(chainDir)
	if err != nil {
		t.Fatal(err)
	}
	var out []chainLink
	for _, link := range links {
		if link.Type != auditchain.EventBatch {
			continue
		}
		bp, err := auditchain.DecodeBatchPayload(link.Payload)
		if err != nil {
			t.Fatal(err)
		}
		leaves, err := auditchain.ReadLeaves(chainDir, bp.FirstLeaf, int(bp.Count))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, chainLink{seq: link.Seq, at: link.UnixNano, leaves: leaves})
	}
	return out
}

// catchUpLinks — README («Copy and restore»): записи source с номерами seqs,
// догнанные после падения, лежат звеньями без чужих листьев (остатков с
// диска, событий подъёма), не длиннее тика по времени приёма, и время звена —
// время приёма его последней записи.
func catchUpLinks(t *testing.T, st *Store, source string, seqs ...uint64) {
	t.Helper()
	want := make(map[string]bool, len(seqs))
	for _, q := range seqs {
		want[strconv.FormatUint(q, 10)] = true
	}
	at := func(ns int64) string { return time.Unix(0, ns).UTC().Format("15:04:05.000") }
	seen := 0
	for _, link := range chainLinks(t, st) {
		var mine []int64
		others := 0
		for _, l := range link.leaves {
			if l.Type == auditchain.EventEvidence && l.Scope == source && want[l.Subject] {
				mine = append(mine, l.UnixNano)
			} else {
				others++
			}
		}
		if len(mine) == 0 {
			continue
		}
		seen += len(mine)
		last := mine[len(mine)-1]
		if others > 0 {
			t.Errorf("звено %d: записи догона в одном звене с %d чужими листьями", link.seq, others)
		}
		if span := time.Duration(last - mine[0]); span > st.cfg.Chain.Tick.D() {
			t.Errorf("звено %d: записи догона за %v по времени приёма — длиннее тика", link.seq, span)
		}
		if link.at != last {
			t.Errorf("звено %d: время %s, а время приёма его последней записи %s", link.seq, at(link.at), at(last))
		}
	}
	if seen != len(seqs) {
		t.Errorf("в цепи %d записей догона из %d", seen, len(seqs))
	}
}

// tokenLinksAlone — README («Bundles over a window of time»): лист токена
// лежит в звене один.
func tokenLinksAlone(t *testing.T, st *Store) {
	t.Helper()
	for _, link := range chainLinks(t, st) {
		for _, l := range link.leaves {
			if l.Type == auditchain.EventTimestamp && len(link.leaves) > 1 {
				t.Errorf("звено %d: лист токена вместе с %d другими листьями", link.seq, len(link.leaves)-1)
			}
		}
	}
}

// leafAt — время первого листа вида typ с предметом scope.
func leafAt(t *testing.T, st *Store, typ auditchain.EventType, scope string) int64 {
	t.Helper()
	for _, link := range chainLinks(t, st) {
		for _, l := range link.leaves {
			if l.Type == typ && l.Scope == scope {
				return l.UnixNano
			}
		}
	}
	t.Fatalf("в цепи нет листа %d от %s", typ, scope)
	return 0
}
