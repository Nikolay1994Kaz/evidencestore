package proof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// R2-G. Перечень проверяющего (-tsa-revoked) называет закреплённый корень
// службы без причины (поле reason пусто — «причины нет»), дата — после меток.
// До диффа: ключ корня под подозрением, меткам нужна POE, без неё пакет не
// проходит. После (keepsEarlierFor: центр без причины — без компрометации):
// метки до даты в силе, пакет проходит без POE.
func TestC2bR2ListedRootNoReason(t *testing.T) {
	w, b := standard(t, nil)
	tr := w.trust()
	list, _ := json.Marshal([]map[string]string{{"cert_sha256": tsa.Fingerprint(w.tsa.Root()), "revoked": w.now.Add(time.Hour).UTC().Format(time.RFC3339)}})
	p := filepath.Join(t.TempDir(), "revoked.json")
	os.WriteFile(p, list, 0o600)
	tr.TSARevocations = tsa.NewRevocations(w.now.Add(48 * time.Hour))
	if err := tr.TSARevocations.AddList(p); err != nil {
		t.Fatal(err)
	}
	r := Verify(b, tr)
	t.Logf("корень в перечне без причины: valid=%v; %s", r.Valid(), revocationCheck(t, r.Checks).Detail)
}
