package message

import (
	"bytes"
	"testing"

	"github.com/ciranda-dev/kolo-mls/internal/schedule"
	"github.com/ciranda-dev/kolo-mls/internal/suite"
	"github.com/ciranda-dev/kolo-mls/internal/testvec"
)

// TestTranscriptHashVectors runs transcript-hashes.json with the full
// AuthenticatedContent decoder (RFC 9420 section 8.2).
func TestTranscriptHashVectors(t *testing.T) {
	var v []struct {
		CipherSuite     uint16      `json:"cipher_suite"`
		ConfirmationKey testvec.Hex `json:"confirmation_key"`
		Content         testvec.Hex `json:"authenticated_content"`
		InterimBefore   testvec.Hex `json:"interim_transcript_hash_before"`
		ConfirmedAfter  testvec.Hex `json:"confirmed_transcript_hash_after"`
		InterimAfter    testvec.Hex `json:"interim_transcript_hash_after"`
	}
	testvec.Load(t, "transcript-hashes.json", &v)
	checked, skipped := 0, 0
	for i, e := range v {
		if e.CipherSuite != suite.ID {
			skipped++
			continue
		}
		checked++
		ac, err := UnmarshalAuthenticatedContent(e.Content)
		if err != nil || ac.Content.ContentType != ContentCommit {
			t.Fatalf("entry %d: %v", i, err)
		}
		in, err := ac.ConfirmedTranscriptHashInput()
		if err != nil {
			t.Fatal(err)
		}
		confirmed := schedule.ConfirmedTranscriptHash(e.InterimBefore, in)
		if !bytes.Equal(confirmed, e.ConfirmedAfter) {
			t.Fatalf("entry %d: confirmed transcript hash differs", i)
		}
		if !suite.VerifyMAC(e.ConfirmationKey, confirmed, ac.Auth.ConfirmationTag) {
			t.Fatalf("entry %d: confirmation tag", i)
		}
		interim, err := schedule.InterimTranscriptHash(confirmed, ac.Auth.ConfirmationTag)
		if err != nil || !bytes.Equal(interim, e.InterimAfter) {
			t.Fatalf("entry %d: interim transcript hash differs: %v", i, err)
		}
		again, _ := ac.Marshal()
		if !bytes.Equal(again, e.Content) {
			t.Fatalf("entry %d: re-encoding differs", i)
		}
	}
	if checked != 1 || skipped != 6 {
		t.Fatalf("transcript-hashes.json: %d suite 1 entries, %d skipped; want 1 and 6", checked, skipped)
	}
}
