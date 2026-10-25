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
	// испорченные файлы ничего не доказывают ни за, ни против.
	heads := map[uint64]PublishedHead{}
	var seqs []uint64
	var fork error
	signed := 0
	for _, h := range w.Heads {
		if auditchain.VerifyStatement(h.Statement, key) != nil {
			continue
		}
		signed++
		seq := h.Statement.HeadSeq
		prev, ok := heads[seq]
		switch {
		case !ok:
			heads[seq] = h
			seqs = append(seqs, seq)
		case prev.Statement.HeadHash != h.Statement.HeadHash && fork == nil:
			fork = fmt.Errorf("the witness holds two different heads number %d (%s and %s), both signed with the store key: the store signed two versions of the chain", seq, prev.Name, h.Name)
		}
	}
	add("the witness holds one version of the chain (no two different heads with one number)", fork,
		fmt.Sprintf("%d distinct heads signed with the store key, %d of %d files are not such heads", len(seqs), len(w.Heads)-signed, len(w.Heads)))
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	// Каждая голова свидетеля, чьё звено есть в пакете, обязана с ним
	// совпасть: иначе пакет — из другой версии цепи.
	first, last := links[0].Seq, links[len(links)-1].Seq
	var err error
	for _, seq := range seqs {
		if seq < first || seq > last {
			continue
		}
		if h := heads[seq]; h.Statement.HeadHash != encodeHash(hashes[seq-first]) {
			err = fmt.Errorf("link %d in the bundle differs from head %d the witness saw (%s): the chain was rewritten after the witness saw it", seq, seq, h.Name)
			break
		}
	}
	// Улику закрепляет первая голова свидетеля не раньше её звена; пакет
	// обязан до неё доходить.
	i := sort.Search(len(seqs), func(i int) bool { return seqs[i] >= evLink })
	if err == nil && i < len(seqs) {
		if a := seqs[i]; a > last {
			err = fmt.Errorf("the bundle ends at link %d, before head %d the witness saw: request a bundle up to it (evidencestore proof -to-head %d)", last, a, a)
		} else {
			r.WitnessHead = a
		}
	}
	detail := "the witness has no head at or after the record's link yet"
	if r.WitnessHead != 0 {
		detail = fmt.Sprintf("head %d", r.WitnessHead)
	}
	add("the chain in the bundle agrees with the heads the witness saw", err, detail)
}
