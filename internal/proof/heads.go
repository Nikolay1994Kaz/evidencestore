package proof

import (
	"crypto/ed25519"
	"fmt"
	"sort"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// Сверка пакета со свидетелем голов (решение 25.10, DECISIONS «Свидетель
// голов»).
//
// Против держателя ключа подписи цепь сама доказывает только время: вторую
// версию цепи он подпишет тем же ключом, метки TSA на ней будут свежие, и
// пакет из неё проверку пройдёт. Свидетель — тот, кто рано получил
// подписанную голову и хранит её вне власти администратора хранилища: канал
// свидетеля (witness.url), газета, копия наружу в чужом хранилище с
// блокировкой. Каждое звено ссылается хэшем на прежнее, поэтому голова у
// свидетеля закрепляет всю цепь до неё: переписать улику раньше этой головы
// значит разойтись со свидетелем.

// Witness — головы, которые проверяющий сам взял у свидетеля: все, какие
// есть, в том числе прежние версии объектов (поверх запертой версии можно
// положить новую, а запертая остаётся).
type Witness struct {
	Heads []PublishedHead
}

// PublishedHead — подписанная голова у свидетеля. Name — откуда она взята
// (имя файла): для отчёта.
type PublishedHead struct {
	Name      string
	Statement auditchain.Statement
}

// checkWitness сверяет пакет с головами свидетеля. evLink — звено улики,
// links и hashes — звенья пакета подряд и их хэши. add — пункт отчёта, как в
// Verify.
func checkWitness(w *Witness, key ed25519.PublicKey, evLink uint64, links []auditchain.Record, hashes [][32]byte,
	r *Report, add func(string, error, string) bool) {
	r.WitnessChecked = true

	// Силу имеют только головы, подписанные ключом хранилища: чужие и
	// испорченные файлы ничего не доказывают ни за, ни против. Под одним
	// номером бывает больше одной головы: тогда хранилище подписало две версии
	// цепи, и сохраняются все.
	versions := map[uint64][]PublishedHead{}
	signed := 0
	for _, h := range w.Heads {
		if auditchain.VerifyStatement(h.Statement, key) != nil {
			continue
		}
		signed++
		seq, known := h.Statement.HeadSeq, false
		for _, v := range versions[seq] {
			known = known || v.Statement.HeadHash == h.Statement.HeadHash
		}
		if !known {
			versions[seq] = append(versions[seq], h)
		}
	}
	seqs := make([]uint64, 0, len(versions))
	for seq := range versions {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	// Каждая голова свидетеля, чьё звено есть в пакете, обязана с ним
	// совпасть — каждая её версия: иначе пакет из другой версии цепи или этот
	// участок цепи существует в двух версиях. Две версии вне участка пакета
	// запись не задевают: её закрепляет голова свидетеля внутри участка, а
	// развилка дальше — замечание в отчёте, а не провал (P-11).
	first, last := links[0].Seq, links[len(links)-1].Seq
	var err error
	for _, seq := range seqs {
		vs := versions[seq]
		if seq < first || seq > last {
			if len(vs) > 1 && r.WitnessFork == 0 {
				r.WitnessFork = seq
			}
			continue
		}
		for _, h := range vs {
			if h.Statement.HeadHash == encodeHash(hashes[seq-first]) {
				continue
			}
			if len(vs) > 1 {
				err = fmt.Errorf("the witness holds two different heads number %d (%s and %s), both signed with the store key: this part of the chain exists in two versions", seq, vs[0].Name, vs[1].Name)
			} else {
				err = fmt.Errorf("link %d in the bundle differs from head %d the witness saw (%s): the chain was rewritten after the witness saw it", seq, seq, h.Name)
			}
			break
		}
		if err != nil {
			break
		}
	}
	// Улику закрепляет первая голова свидетеля не раньше её звена; пакет
	// обязан до неё доходить.
	i := sort.Search(len(seqs), func(i int) bool { return seqs[i] >= evLink })
	switch {
	case err != nil:
	case i == len(seqs):
		r.WitnessNone = true
	case seqs[i] > last:
		err = fmt.Errorf("the bundle ends at link %d, before head %d the witness saw: request a bundle up to it (evidencestore proof -to-head %d)", last, seqs[i], seqs[i])
	default:
		r.WitnessHead = seqs[i]
	}
	counted := fmt.Sprintf("%d heads signed with the store key, %d of %d files are not such heads", len(seqs), len(w.Heads)-signed, len(w.Heads))
	detail := "the witness has no head at or after the record's link yet; " + counted
	if r.WitnessHead != 0 {
		detail = fmt.Sprintf("head %d; %s", r.WitnessHead, counted)
	}
	add("the chain in the bundle agrees with the heads the witness saw", err, detail)
}
