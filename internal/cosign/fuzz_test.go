package cosign

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// Фаззинг разбора того, что свидетель принимает от кого угодно по сети
// (тело add-checkpoint, заметка точки) и что аудитор передаёт флагом (ключ
// проверки). Разбор не падает, а принятое переписывается обратно в те же
// байты: строгий разбор — один способ записи.

// fuzzNote — заметка точки с подписью журнала.
func fuzzNote(t testing.TB) []byte {
	pub, priv, _ := ed25519.GenerateKey(nil)
	text := CheckpointText("example.com/log", 7, [32]byte{1, 2, 3})
	sig := ed25519.Sign(priv, text)
	return append(append(text, '\n'), LogSignature("example.com/log", pub, sig)...)
}

func FuzzParseAddCheckpoint(f *testing.F) {
	note := fuzzNote(f)
	f.Add(AddCheckpoint(0, nil, note))
	f.Add(AddCheckpoint(5, [][32]byte{{9}, {8}}, note))
	f.Add([]byte("old 01\n\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		old, proof, n, err := ParseAddCheckpoint(body)
		if err != nil {
			return
		}
		if back := AddCheckpoint(old, proof, n); !bytes.Equal(back, body) {
			t.Fatalf("accepted a body that does not write back the same:\n%q\n%q", body, back)
		}
		if text, sigs, err := SplitNote(n); err == nil {
			ParseCheckpointText(text)
			for _, l := range sigs {
				ParseSigLine(l)
			}
		}
	})
}

func FuzzParseCheckpointText(f *testing.F) {
	f.Add(CheckpointText("example.com/log", 7, [32]byte{1}))
	f.Add([]byte("example.com/log\n007\nAAAA\n"))
	f.Fuzz(func(t *testing.T, text []byte) {
		origin, size, root, err := ParseCheckpointText(text)
		if err != nil {
			return
		}
		if back := CheckpointText(origin, size, root); !bytes.Equal(back, text) {
			t.Fatalf("accepted a checkpoint that does not write back the same:\n%q\n%q", text, back)
		}
	})
}

func FuzzParseVerifier(f *testing.F) {
	pub, _, _ := ed25519.GenerateKey(nil)
	f.Add(Verifier{Name: "witness.example/w1", ID: KeyID("witness.example/w1", TypeCosignatureV1, pub), Key: pub}.String())
	f.Add("a+00000000+AA==")
	f.Fuzz(func(t *testing.T, vkey string) {
		v, err := ParseVerifier(vkey)
		if err != nil {
			return
		}
		if v.String() != vkey {
			t.Fatalf("accepted a key that does not write back the same: %q, %q", vkey, v.String())
		}
	})
}
