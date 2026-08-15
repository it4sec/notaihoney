package evidence

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	BWJFileHeaderSize   = 64
	BWJRecordHeaderSize = 64
	BWJMaxDataPayload   = 65536
	bwjVersion          = 1
)

var (
	bwjFileMagic   = [8]byte{'N', 'A', 'I', 'H', 'B', 'W', 'J', '1'}
	bwjRecordMagic = [4]byte{'B', 'W', 'J', 'R'}
)

type ID [16]byte

func NewID() (ID, error) {
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		return ID{}, err
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id, nil
}

func FormatID(id ID) string {
	raw := hex.EncodeToString(id[:])
	return raw[0:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:32]
}

func ParseID(s string) (ID, error) {
	var id ID
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return id, fmt.Errorf("invalid id length")
	}
	decoded, err := hex.DecodeString(clean)
	if err != nil {
		return ID{}, fmt.Errorf("invalid id: %w", err)
	}
	copy(id[:], decoded)
	return id, nil
}

type RecordType uint8

const (
	RecordConnectionOpen  RecordType = 1
	RecordData            RecordType = 2
	RecordConnectionClose RecordType = 3
	RecordParserError     RecordType = 4
	RecordLimitReached    RecordType = 5
)

type Direction uint8

const (
	DirectionNA       Direction = 0
	DirectionInbound  Direction = 1
	DirectionOutbound Direction = 2
)

const (
	FlagTruncated    uint8 = 0x01
	FlagParserFailed uint8 = 0x02
	FlagStreaming    uint8 = 0x04
	FlagLimit        uint8 = 0x08
	reservedFlags          = 0xf0
)

type CloseReason uint16

const (
	CloseUnspecified     CloseReason = 0
	CloseRemote          CloseReason = 1
	CloseNormal          CloseReason = 2
	CloseIdleTimeout     CloseReason = 3
	CloseHeaderTimeout   CloseReason = 4
	CloseBodyTimeout     CloseReason = 5
	CloseWriteTimeout    CloseReason = 6
	CloseTLSError        CloseReason = 7
	CloseParserFailure   CloseReason = 8
	CloseLimitReached    CloseReason = 9
	CloseShutdown        CloseReason = 10
	CloseEvidenceFailure CloseReason = 11
	CloseInternalError   CloseReason = 12
	CloseCaptureFailure  CloseReason = 13
	CloseStorageFailure  CloseReason = 14
)

// Limit codes are versioned writer constants carried only in engine-generated
// BWJ metadata, never attacker-controlled payloads.
type LimitCode uint16

const (
	LimitHeaderBytes LimitCode = 1 + iota
	LimitBodyBytes
	LimitRequestsPerConnection
	LimitConnectionLifetime
	LimitConnectionBytes
	LimitResponseBytes
	LimitStreamLifetime
	LimitPostFailureCaptureBytes
	LimitHeaderTimeout
	LimitBodyTimeout
	LimitIdleTimeout
	LimitWriteTimeout
)

type ParserCode uint16

const (
	ParserInvalidHTTP ParserCode = 1 + iota
	ParserUnsupportedHTTPVersion
	ParserUnsupportedExpectation
	ParserProhibitedConnect
)

type BWJWriter struct {
	mu             sync.Mutex
	directory      string
	runSessionID   ID
	rotateSize     int64
	rotateDuration time.Duration
	file           *os.File
	fileSequence   uint64
	recordSequence uint64
	createdAt      time.Time
	bytesWritten   int64
	closed         bool
	failed         error
}

func NewBWJWriter(directory string, runSessionID ID, rotateSizeBytes int64, rotateSeconds int) (*BWJWriter, error) {
	if err := CheckWritable(directory); err != nil {
		return nil, err
	}
	w := &BWJWriter{
		directory:      directory,
		runSessionID:   runSessionID,
		rotateSize:     rotateSizeBytes,
		rotateDuration: time.Duration(rotateSeconds) * time.Second,
	}
	if err := w.openNextLocked(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *BWJWriter) RunSessionID() ID { return w.runSessionID }

func (w *BWJWriter) CurrentFilename() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return ""
	}
	return filepath.Base(w.file.Name())
}

func (w *BWJWriter) WriteConnectionOpen(connectionID ID) error {
	return w.writeRecord(RecordConnectionOpen, DirectionNA, 0, connectionID, ID{}, nil)
}

func (w *BWJWriter) WriteConnectionClose(connectionID ID, reason CloseReason) error {
	payload := make([]byte, 2)
	binary.LittleEndian.PutUint16(payload, uint16(reason))
	return w.writeRecord(RecordConnectionClose, DirectionNA, 0, connectionID, ID{}, payload)
}

func (w *BWJWriter) WriteParserError(connectionID ID, code ParserCode, position uint64) error {
	payload := make([]byte, 10)
	binary.LittleEndian.PutUint16(payload[0:2], uint16(code))
	binary.LittleEndian.PutUint64(payload[2:10], position)
	return w.writeRecord(RecordParserError, DirectionNA, 0, connectionID, ID{}, payload)
}

func (w *BWJWriter) WriteLimit(connectionID ID, code LimitCode, observed uint64) error {
	payload := make([]byte, 10)
	binary.LittleEndian.PutUint16(payload[0:2], uint16(code))
	binary.LittleEndian.PutUint64(payload[2:10], observed)
	return w.writeRecord(RecordLimitReached, DirectionNA, FlagLimit, connectionID, ID{}, payload)
}

func (w *BWJWriter) WriteData(connectionID, requestID ID, direction Direction, flags uint8, data []byte) error {
	if direction != DirectionInbound && direction != DirectionOutbound {
		return fmt.Errorf("invalid DATA direction %d", direction)
	}
	for len(data) > 0 {
		n := len(data)
		if n > BWJMaxDataPayload {
			n = BWJMaxDataPayload
		}
		if err := w.writeRecord(RecordData, direction, flags, connectionID, requestID, data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func (w *BWJWriter) writeRecord(recordType RecordType, direction Direction, flags uint8, connectionID, requestID ID, payload []byte) error {
	if flags&reservedFlags != 0 {
		return fmt.Errorf("reserved BWJ flags set")
	}
	if err := validatePayload(recordType, payload); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	if w.failed != nil {
		return w.failed
	}
	recordBytes := int64(BWJRecordHeaderSize + len(payload))
	if w.shouldRotateLocked(recordBytes) {
		if err := w.rotateLocked(); err != nil {
			return w.failLocked(err)
		}
	}
	w.recordSequence++
	header := make([]byte, BWJRecordHeaderSize)
	copy(header[0:4], bwjRecordMagic[:])
	header[4] = bwjVersion
	header[5] = byte(recordType)
	header[6] = byte(direction)
	header[7] = flags
	binary.LittleEndian.PutUint64(header[8:16], uint64(time.Now().UnixNano()))
	binary.LittleEndian.PutUint64(header[16:24], w.recordSequence)
	copy(header[24:40], connectionID[:])
	copy(header[40:56], requestID[:])
	binary.LittleEndian.PutUint64(header[56:64], uint64(len(payload)))

	// A record is acknowledged only after its complete header and payload have
	// passed through this serialized file-descriptor write loop.
	if err := writeFull(w.file, header); err != nil {
		return w.failLocked(fmt.Errorf("BWJ_WRITE_FAILED header: %w", err))
	}
	if len(payload) > 0 {
		if err := writeFull(w.file, payload); err != nil {
			return w.failLocked(fmt.Errorf("BWJ_WRITE_FAILED payload: %w", err))
		}
	}
	w.bytesWritten += recordBytes
	return nil
}

func (w *BWJWriter) failLocked(err error) error {
	if err != nil && w.failed == nil {
		w.failed = err
	}
	return w.failed
}

func (w *BWJWriter) shouldRotateLocked(next int64) bool {
	if w.file == nil {
		return true
	}
	if w.rotateSize > 0 && w.bytesWritten > BWJFileHeaderSize && w.bytesWritten+next > w.rotateSize {
		return true
	}
	return w.rotateDuration > 0 && time.Since(w.createdAt) >= w.rotateDuration
}

func (w *BWJWriter) rotateLocked() error {
	if w.file != nil {
		if err := w.file.Sync(); err != nil {
			return fmt.Errorf("BWJ_WRITE_FAILED sync before rotation: %w", err)
		}
		if err := w.file.Close(); err != nil {
			return fmt.Errorf("BWJ_WRITE_FAILED close before rotation: %w", err)
		}
		w.file = nil
	}
	return w.openNextLocked()
}

func (w *BWJWriter) openNextLocked() error {
	w.fileSequence++
	name := fmt.Sprintf("bwj_%s_%020d.bwj", FormatID(w.runSessionID), w.fileSequence)
	path := filepath.Join(w.directory, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("BWJ_WRITE_FAILED create %s: %w", path, err)
	}
	header := make([]byte, BWJFileHeaderSize)
	copy(header[0:8], bwjFileMagic[:])
	binary.LittleEndian.PutUint16(header[8:10], bwjVersion)
	binary.LittleEndian.PutUint16(header[10:12], BWJFileHeaderSize)
	binary.LittleEndian.PutUint64(header[12:20], uint64(time.Now().UnixNano()))
	copy(header[20:36], w.runSessionID[:])
	binary.LittleEndian.PutUint64(header[36:44], w.fileSequence)
	if err := writeFull(f, header); err != nil {
		f.Close()
		return fmt.Errorf("BWJ_WRITE_FAILED file header: %w", err)
	}
	w.file = f
	w.recordSequence = 0
	w.createdAt = time.Now()
	w.bytesWritten = BWJFileHeaderSize
	return nil
}

func (w *BWJWriter) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return w.failed
	}
	return errors.Join(w.failed, w.file.Sync())
}

func (w *BWJWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.file == nil {
		return w.failed
	}
	syncErr := w.file.Sync()
	closeErr := w.file.Close()
	w.file = nil
	return errors.Join(w.failed, syncErr, closeErr)
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func validatePayload(recordType RecordType, payload []byte) error {
	switch recordType {
	case RecordConnectionOpen:
		if len(payload) != 0 {
			return fmt.Errorf("CONNECTION_OPEN payload must be empty")
		}
	case RecordData:
		if len(payload) > BWJMaxDataPayload {
			return fmt.Errorf("DATA payload exceeds %d bytes", BWJMaxDataPayload)
		}
	case RecordConnectionClose:
		if len(payload) != 2 {
			return fmt.Errorf("CONNECTION_CLOSE payload must be 2 bytes")
		}
	case RecordParserError, RecordLimitReached:
		if len(payload) != 10 {
			return fmt.Errorf("metadata payload must be 10 bytes")
		}
	default:
		return fmt.Errorf("unsupported BWJ record type %d", recordType)
	}
	return nil
}

type FileHeader struct {
	CreatedTimeNS int64
	RunSessionID  ID
	FileSequence  uint64
}

type Record struct {
	Type         RecordType
	Direction    Direction
	Flags        uint8
	TimestampNS  int64
	Sequence     uint64
	ConnectionID ID
	RequestID    ID
	Payload      []byte
}

type ReadResult struct {
	Header        FileHeader
	Records       []Record
	TruncatedTail bool
}

func ReadBWJFile(path string) (ReadResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return ReadResult{}, err
	}
	defer f.Close()
	headerBytes := make([]byte, BWJFileHeaderSize)
	if _, err := io.ReadFull(f, headerBytes); err != nil {
		return ReadResult{}, fmt.Errorf("read BWJ header: %w", err)
	}
	if string(headerBytes[0:8]) != string(bwjFileMagic[:]) {
		return ReadResult{}, fmt.Errorf("invalid BWJ file magic")
	}
	if binary.LittleEndian.Uint16(headerBytes[8:10]) != bwjVersion || binary.LittleEndian.Uint16(headerBytes[10:12]) != BWJFileHeaderSize {
		return ReadResult{}, fmt.Errorf("unsupported BWJ header version or length")
	}
	var result ReadResult
	result.Header.CreatedTimeNS = int64(binary.LittleEndian.Uint64(headerBytes[12:20]))
	copy(result.Header.RunSessionID[:], headerBytes[20:36])
	result.Header.FileSequence = binary.LittleEndian.Uint64(headerBytes[36:44])
	for _, b := range headerBytes[44:64] {
		if b != 0 {
			return ReadResult{}, fmt.Errorf("non-zero reserved BWJ file header bytes")
		}
	}

	var lastSequence uint64
	for {
		rh := make([]byte, BWJRecordHeaderSize)
		n, err := io.ReadFull(f, rh)
		if err == io.EOF && n == 0 {
			break
		}
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			result.TruncatedTail = true
			break
		}
		if err != nil {
			return ReadResult{}, err
		}
		if string(rh[0:4]) != string(bwjRecordMagic[:]) || rh[4] != bwjVersion {
			return ReadResult{}, fmt.Errorf("invalid BWJ record magic/version")
		}
		r := Record{Type: RecordType(rh[5]), Direction: Direction(rh[6]), Flags: rh[7]}
		if r.Flags&reservedFlags != 0 {
			return ReadResult{}, fmt.Errorf("reserved BWJ record flags are non-zero")
		}
		r.TimestampNS = int64(binary.LittleEndian.Uint64(rh[8:16]))
		r.Sequence = binary.LittleEndian.Uint64(rh[16:24])
		if r.Sequence == 0 || r.Sequence <= lastSequence {
			return ReadResult{}, fmt.Errorf("non-monotonic BWJ record sequence")
		}
		lastSequence = r.Sequence
		copy(r.ConnectionID[:], rh[24:40])
		copy(r.RequestID[:], rh[40:56])
		length := binary.LittleEndian.Uint64(rh[56:64])
		if length > BWJMaxDataPayload && r.Type == RecordData {
			return ReadResult{}, fmt.Errorf("DATA payload length exceeds %d", BWJMaxDataPayload)
		}
		if length > 10 && r.Type != RecordData {
			return ReadResult{}, fmt.Errorf("metadata payload length is invalid")
		}
		r.Payload = make([]byte, int(length))
		if length > 0 {
			if _, err := io.ReadFull(f, r.Payload); err != nil {
				if err == io.ErrUnexpectedEOF || err == io.EOF {
					result.TruncatedTail = true
					break
				}
				return ReadResult{}, err
			}
		}
		if err := validatePayload(r.Type, r.Payload); err != nil {
			return ReadResult{}, err
		}
		if r.Type == RecordData && r.Direction != DirectionInbound && r.Direction != DirectionOutbound {
			return ReadResult{}, fmt.Errorf("invalid DATA direction")
		}
		if r.Type != RecordData && r.Direction != DirectionNA {
			return ReadResult{}, fmt.Errorf("metadata record direction must be not-applicable")
		}
		result.Records = append(result.Records, r)
	}
	return result, nil
}

func SortBWJResults(results []ReadResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Header.RunSessionID != results[j].Header.RunSessionID {
			return FormatID(results[i].Header.RunSessionID) < FormatID(results[j].Header.RunSessionID)
		}
		return results[i].Header.FileSequence < results[j].Header.FileSequence
	})
}
