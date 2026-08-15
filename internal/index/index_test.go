package index

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"notaihoney/internal/evidence"
)

func TestBWJReconstructionAcrossRotation(t *testing.T) {
	dir := t.TempDir()
	run, _ := evidence.NewID()
	conn, _ := evidence.NewID()
	w, err := evidence.NewBWJWriter(dir, run, 200, 3600)
	if err != nil {
		t.Fatal(err)
	}
	_ = w.WriteConnectionOpen(conn)
	_ = w.WriteData(conn, evidence.ID{}, evidence.DirectionInbound, 0, []byte("request-one"))
	_ = w.WriteData(conn, evidence.ID{}, evidence.DirectionInbound, 0, []byte("request-two"))
	_ = w.WriteData(conn, evidence.ID{}, evidence.DirectionOutbound, 0, []byte("response"))
	_ = w.Close()
	streamsByConnection, err := reconstructStreams(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := streamKey{runSessionID: evidence.FormatID(run), connectionID: evidence.FormatID(conn)}
	stream := streamsByConnection[key]
	if !bytes.Equal(stream.inbound, []byte("request-onerequest-two")) || !bytes.Equal(stream.outbound, []byte("response")) {
		t.Fatalf("bad reconstruction: in=%q out=%q", stream.inbound, stream.outbound)
	}
}

func TestRequestSHA256DerivationAndResponseVerificationPrimitive(t *testing.T) {
	stream := []byte("prefix-request-suffix")
	got, err := streamSliceSHA256(stream, 7, 7)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("request"))
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("hash=%s want=%s", got, want)
	}
	if _, err := streamSliceSHA256(stream, -1, 2); err == nil {
		t.Fatal("negative range must fail")
	}
	if _, err := streamSliceSHA256(stream, 3, int64(len(stream))); err == nil {
		t.Fatal("out-of-bounds range must fail")
	}
}
