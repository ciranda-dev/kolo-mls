package framing

import (
	"bytes"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
)

// TestSecretTreeSenderData checks the sender data key and nonce of
// secret-tree.json (RFC 9420 section 6.3.2).
func TestSecretTreeSenderData(t *testing.T) {
	var v []struct {
		CipherSuite uint16 `json:"cipher_suite"`
		SenderData  struct {
			Secret     testvec.Hex `json:"sender_data_secret"`
			Ciphertext testvec.Hex `json:"ciphertext"`
			Key        testvec.Hex `json:"key"`
			Nonce      testvec.Hex `json:"nonce"`
		} `json:"sender_data"`
	}
	testvec.Load(t, "secret-tree.json", &v)
	checked, skipped := 0, 0
	for i, e := range v {
		if e.CipherSuite != suite.ID {
			skipped++
			continue
		}
		checked++
		key, nonce, err := senderDataKey(e.SenderData.Secret, e.SenderData.Ciphertext)
		if err != nil || !bytes.Equal(key, e.SenderData.Key) || !bytes.Equal(nonce, e.SenderData.Nonce) {
			t.Fatalf("entry %d: sender data key or nonce differs: %v", i, err)
		}
	}
	if checked != 3 || skipped != 18 {
		t.Fatalf("secret-tree.json: %d suite 1 entries, %d skipped; want 3 and 18", checked, skipped)
	}
}
