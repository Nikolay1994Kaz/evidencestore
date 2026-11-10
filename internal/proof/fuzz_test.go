package proof

import (
	"encoding/json"
	"testing"
	"time"
)

// Пакет приходит к аудитору от хранилища, то есть от того, кого проверяют:
// esverify разбирает любой JSON без паники, а отчёт VERIFIED даёт только
// пакету, который сходится с ключом хранилища. Сведения об отзыве даны:
// разбор пути отзыва и POE — тоже под фаззингом.
func FuzzVerifyBundle(f *testing.F) {
	w, b := standard(f, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	tr := w.trust()
	tr.TSARevocations = compromised(f, w.tsa, w.now.Add(time.Hour), w.now.Add(48*time.Hour))
	seed, err := json.Marshal(b)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	b.Archive = []ArchiveStamp{{HeadSeq: 5, Root: make([]byte, 32), Token: []byte{0x30, 0x00}}}
	b.Cosignatures = []Cosignature{{Name: "w", Size: 5, Root: make([]byte, 31), Sig: []byte{1, 2, 3, 4}}}
	more, _ := json.Marshal(b)
	f.Add(more)
	f.Fuzz(func(t *testing.T, data []byte) {
		var fb Bundle
		if json.Unmarshal(data, &fb) != nil {
			return
		}
		r := Verify(fb, tr)
		_ = r.Text()
	})
}
