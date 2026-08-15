package evidence

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type shortWriter struct {
	buf bytes.Buffer
	max int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.buf.Write(p)
}

func TestBWJHeaderRecordAndRotation(t *testing.T) {
	dir := t.TempDir()
	run, _ := NewID()
	conn, _ := NewID()
	w, err := NewBWJWriter(dir, run, 200, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteConnectionOpen(conn); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x41}, BWJMaxDataPayload+1)
	if err := w.WriteData(conn, ID{}, DirectionInbound, 0, payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.bwj"))
	if len(paths) < 2 {
		t.Fatalf("expected rotation, got %d files", len(paths))
	}
	for _, path := range paths {
		result, err := ReadBWJFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if result.Header.RunSessionID != run {
			t.Fatal("run session id mismatch")
		}
		for _, record := range result.Records {
			if record.Type == RecordData && len(record.Payload) > BWJMaxDataPayload {
				t.Fatal("oversized DATA record")
			}
		}
	}
	first, _ := os.ReadFile(paths[0])
	if len(first) < BWJFileHeaderSize || string(first[:8]) != "NAIHBWJ1" {
		t.Fatal("bad file header")
	}
	if binary.LittleEndian.Uint16(first[10:12]) != BWJFileHeaderSize {
		t.Fatal("header is not exactly 64 bytes")
	}
}

func TestWriteFullHandlesShortWrites(t *testing.T) {
	w := &shortWriter{max: 3}
	data := []byte("abcdefghij")
	if err := writeFull(w, data); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.buf.Bytes(), data) {
		t.Fatal("short-write loop lost bytes")
	}
}

func TestTruncatedFinalRecordPreservesEarlierRecords(t *testing.T) {
	dir := t.TempDir()
	run, _ := NewID()
	conn, _ := NewID()
	w, err := NewBWJWriter(dir, run, 1<<20, 3600)
	if err != nil {
		t.Fatal(err)
	}
	_ = w.WriteConnectionOpen(conn)
	_ = w.WriteData(conn, ID{}, DirectionInbound, 0, []byte("hello"))
	path := filepath.Join(dir, w.CurrentFilename())
	_ = w.Close()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("BWJR\x01\x02"))
	_ = f.Close()
	result, err := ReadBWJFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !result.TruncatedTail || len(result.Records) != 2 {
		t.Fatalf("truncated=%v records=%d", result.TruncatedTail, len(result.Records))
	}
}

func TestWriteFullZeroProgress(t *testing.T) {
	if err := writeFull(zeroWriter{}, []byte("x")); err != io.ErrShortWrite {
		t.Fatalf("got %v", err)
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestSerializedWriterProducesMonotonicRecordSequence(t *testing.T) {
	dir := t.TempDir()
	run, _ := NewID()
	conn, _ := NewID()
	w, err := NewBWJWriter(dir, run, 1<<20, 3600)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(b byte) {
			defer wg.Done()
			if err := w.WriteData(conn, ID{}, DirectionInbound, 0, []byte{b}); err != nil {
				t.Errorf("write: %v", err)
			}
		}(byte(i))
	}
	wg.Wait()
	path := filepath.Join(dir, w.CurrentFilename())
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := ReadBWJFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 8 {
		t.Fatalf("records=%d", len(result.Records))
	}
	for i, record := range result.Records {
		if record.Sequence != uint64(i+1) {
			t.Fatalf("record[%d] sequence=%d", i, record.Sequence)
		}
	}
}

func TestRecordHeaderIs64BytesAndLittleEndian(t *testing.T) {
	dir := t.TempDir()
	run, _ := NewID()
	conn, _ := NewID()
	w, err := NewBWJWriter(dir, run, 1<<20, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteData(conn, ID{}, DirectionInbound, 0, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, w.CurrentFilename())
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < BWJFileHeaderSize+BWJRecordHeaderSize+3 {
		t.Fatal("record shorter than fixed header plus payload")
	}
	rh := data[BWJFileHeaderSize : BWJFileHeaderSize+BWJRecordHeaderSize]
	if string(rh[:4]) != "BWJR" || rh[4] != 1 || rh[5] != byte(RecordData) || rh[6] != byte(DirectionInbound) {
		t.Fatalf("invalid fixed record header: %x", rh)
	}
	if got := binary.LittleEndian.Uint64(rh[56:64]); got != 3 {
		t.Fatalf("payload length=%d", got)
	}
}
