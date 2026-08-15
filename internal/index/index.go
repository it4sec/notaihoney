package index

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	_ "github.com/mattn/go-sqlite3"

	"notaihoney/internal/config"
	"notaihoney/internal/evidence"
)

const schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS connections (
    connection_id       TEXT PRIMARY KEY,
    sensor_id           TEXT NOT NULL,
    run_session_id      TEXT NOT NULL,
    config_sha256       TEXT NOT NULL,
    service_id          TEXT NOT NULL,
    opened_at_ns        INTEGER NOT NULL,
    closed_at_ns        INTEGER,
    src_ip              TEXT NOT NULL,
    src_port            INTEGER NOT NULL,
    dst_ip              TEXT NOT NULL,
    dst_port             INTEGER NOT NULL,
    listener_protocol   TEXT NOT NULL,
    bytes_in            INTEGER NOT NULL DEFAULT 0,
    bytes_out           INTEGER NOT NULL DEFAULT 0,
    request_count       INTEGER NOT NULL DEFAULT 0,
    close_reason        TEXT
);
CREATE TABLE IF NOT EXISTS exchanges (
    request_id              TEXT PRIMARY KEY,
    connection_id           TEXT NOT NULL,
    timestamp_start_ns      INTEGER NOT NULL,
    timestamp_end_ns        INTEGER,
    http_version            TEXT,
    method                  TEXT,
    path                    TEXT,
    query_metadata_json     TEXT,
    content_type            TEXT,
    content_length          INTEGER,
    request_headers_json    TEXT,
    matched_route           TEXT,
    classification          TEXT,
    response_source         TEXT,
    response_sequence       INTEGER,
    response_status         INTEGER,
    request_bytes           INTEGER NOT NULL DEFAULT 0,
    response_bytes          INTEGER NOT NULL DEFAULT 0,
    request_sha256          TEXT,
    response_sha256         TEXT,
    request_stream_start    INTEGER,
    request_stream_length   INTEGER,
    response_stream_start   INTEGER,
    response_stream_length  INTEGER,
    request_complete        INTEGER NOT NULL DEFAULT 0,
    response_complete       INTEGER NOT NULL DEFAULT 0,
    write_error             TEXT,
    FOREIGN KEY (connection_id) REFERENCES connections(connection_id)
);
CREATE INDEX IF NOT EXISTS idx_connections_opened ON connections(opened_at_ns);
CREATE INDEX IF NOT EXISTS idx_connections_source_ip ON connections(src_ip);
CREATE INDEX IF NOT EXISTS idx_connections_service ON connections(service_id);
CREATE INDEX IF NOT EXISTS idx_connections_dst_port ON connections(dst_port);
CREATE INDEX IF NOT EXISTS idx_exchanges_timestamp ON exchanges(timestamp_start_ns);
CREATE INDEX IF NOT EXISTS idx_exchanges_connection ON exchanges(connection_id);
CREATE INDEX IF NOT EXISTS idx_exchanges_method_path ON exchanges(method, path);
CREATE INDEX IF NOT EXISTS idx_exchanges_classification ON exchanges(classification);
CREATE INDEX IF NOT EXISTS idx_exchanges_status ON exchanges(response_status);
`

type streamKey struct {
	runSessionID string
	connectionID string
}

type streams struct {
	inbound  []byte
	outbound []byte
}

type connectionRow struct {
	connectionID string
	sensorID     string
	runSessionID string
	configSHA256 string
	serviceID    string
	openedAt     int64
	closedAt     *int64
	srcIP        string
	srcPort      int
	dstIP        string
	dstPort      int
	protocol     string
	bytesIn      int64
	bytesOut     int64
	requestCount int
	closeReason  string
}

type exchangeRow struct {
	event         evidence.Event
	requestSHA256 string
}

func Run(cfg *config.Config) error {
	path := config.SQLitePath(cfg)
	if path == "" {
		return fmt.Errorf("CONFIG_INVALID analysis.sqlite.path is required for index mode")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("create SQLite directory: %w", err)
	}
	connections, exchanges, err := readStructuredEvents(cfg.Evidence.JSONL.Directory)
	if err != nil {
		return err
	}
	wire, err := reconstructStreams(cfg.Evidence.WireJournal.Directory)
	if err != nil {
		return err
	}
	for i := range exchanges {
		event := &exchanges[i].event
		key := streamKey{runSessionID: event.RunSessionID, connectionID: event.ConnectionID}
		stream := wire[key]
		if event.RequestComplete {
			hash, err := streamSliceSHA256(stream.inbound, event.RequestStreamStart, event.RequestStreamLength)
			if err != nil {
				return fmt.Errorf("offline request range request_id=%s: %w", event.RequestID, err)
			}
			exchanges[i].requestSHA256 = hash
		}
		if event.ResponseSHA256 != "" {
			actual, err := streamSliceSHA256(stream.outbound, event.ResponseStreamStart, event.ResponseStreamLength)
			if err != nil {
				return fmt.Errorf("offline response range request_id=%s: %w", event.RequestID, err)
			}
			if actual != event.ResponseSHA256 {
				return fmt.Errorf("response SHA-256 mismatch request_id=%s", event.RequestID)
			}
		}
		if _, ok := connections[event.ConnectionID]; !ok {
			connections[event.ConnectionID] = connectionRow{
				connectionID: event.ConnectionID,
				sensorID:     event.SensorID,
				runSessionID: event.RunSessionID,
				configSHA256: event.ConfigSHA256,
				serviceID:    event.ServiceID,
				openedAt:     event.TimestampStartNS,
			}
		}
	}
	return writeSQLite(path, connections, exchanges)
}

func streamSliceSHA256(stream []byte, start, length int64) (string, error) {
	if start < 0 || length < 0 || start > int64(len(stream)) || length > int64(len(stream))-start {
		return "", fmt.Errorf("stream range out of bounds start=%d length=%d stream_length=%d", start, length, len(stream))
	}
	sum := sha256.Sum256(stream[start : start+length])
	return hex.EncodeToString(sum[:]), nil
}

func readStructuredEvents(directory string) (map[string]connectionRow, []exchangeRow, error) {
	paths, err := filepath.Glob(filepath.Join(directory, "*.jsonl"))
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(paths)
	connections := make(map[string]connectionRow)
	exchanges := make([]exchangeRow, 0)
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
		for scanner.Scan() {
			var event evidence.Event
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				f.Close()
				return nil, nil, fmt.Errorf("decode JSONL %s: %w", path, err)
			}
			switch event.EventType {
			case "connection_open":
				connections[event.ConnectionID] = connectionRow{
					connectionID: event.ConnectionID,
					sensorID:     event.SensorID,
					runSessionID: event.RunSessionID,
					configSHA256: event.ConfigSHA256,
					serviceID:    event.ServiceID,
					openedAt:     event.TimestampNS,
					srcIP:        event.SourceIP,
					srcPort:      event.SourcePort,
					dstIP:        event.DestinationIP,
					dstPort:      event.DestinationPort,
					protocol:     event.ListenerProtocol,
				}
			case "connection_close":
				row := connections[event.ConnectionID]
				if row.connectionID == "" {
					row.connectionID = event.ConnectionID
					row.sensorID = event.SensorID
					row.runSessionID = event.RunSessionID
					row.configSHA256 = event.ConfigSHA256
					row.serviceID = event.ServiceID
					row.openedAt = event.TimestampNS
				}
				closed := event.TimestampNS
				row.closedAt = &closed
				row.bytesIn = event.BytesIn
				row.bytesOut = event.BytesOut
				row.requestCount = event.RequestCount
				row.closeReason = event.CloseReason
				connections[event.ConnectionID] = row
			case "exchange":
				exchanges = append(exchanges, exchangeRow{event: event})
			}
		}
		if err := scanner.Err(); err != nil {
			f.Close()
			return nil, nil, err
		}
		if err := f.Close(); err != nil {
			return nil, nil, err
		}
	}
	return connections, exchanges, nil
}

func reconstructStreams(directory string) (map[streamKey]streams, error) {
	paths, err := filepath.Glob(filepath.Join(directory, "bwj_*.bwj"))
	if err != nil {
		return nil, err
	}
	type item struct {
		result evidence.ReadResult
		path   string
	}
	items := make([]item, 0, len(paths))
	for _, path := range paths {
		result, err := evidence.ReadBWJFile(path)
		if err != nil {
			return nil, fmt.Errorf("read BWJ %s: %w", path, err)
		}
		items = append(items, item{result: result, path: path})
	}
	sort.Slice(items, func(i, j int) bool {
		ri, rj := items[i].result.Header, items[j].result.Header
		if ri.RunSessionID != rj.RunSessionID {
			return evidence.FormatID(ri.RunSessionID) < evidence.FormatID(rj.RunSessionID)
		}
		return ri.FileSequence < rj.FileSequence
	})
	out := make(map[streamKey]streams)
	for _, item := range items {
		runID := evidence.FormatID(item.result.Header.RunSessionID)
		for _, record := range item.result.Records {
			if record.Type != evidence.RecordData {
				continue
			}
			key := streamKey{runSessionID: runID, connectionID: evidence.FormatID(record.ConnectionID)}
			stream := out[key]
			if record.Direction == evidence.DirectionInbound {
				stream.inbound = append(stream.inbound, record.Payload...)
			} else if record.Direction == evidence.DirectionOutbound {
				stream.outbound = append(stream.outbound, record.Payload...)
			}
			out[key] = stream
		}
	}
	return out, nil
}

func writeSQLite(path string, connections map[string]connectionRow, exchanges []exchangeRow) error {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	connectionIDs := make([]string, 0, len(connections))
	for id := range connections {
		connectionIDs = append(connectionIDs, id)
	}
	sort.Strings(connectionIDs)
	for _, id := range connectionIDs {
		r := connections[id]
		_, err := tx.Exec(`INSERT INTO connections (
connection_id,sensor_id,run_session_id,config_sha256,service_id,opened_at_ns,closed_at_ns,
src_ip,src_port,dst_ip,dst_port,listener_protocol,bytes_in,bytes_out,request_count,close_reason)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(connection_id) DO UPDATE SET
sensor_id=excluded.sensor_id,
run_session_id=excluded.run_session_id,
config_sha256=excluded.config_sha256,
service_id=excluded.service_id,
opened_at_ns=excluded.opened_at_ns,
closed_at_ns=excluded.closed_at_ns,
src_ip=excluded.src_ip,
src_port=excluded.src_port,
dst_ip=excluded.dst_ip,
dst_port=excluded.dst_port,
listener_protocol=excluded.listener_protocol,
bytes_in=excluded.bytes_in,
bytes_out=excluded.bytes_out,
request_count=excluded.request_count,
close_reason=excluded.close_reason`,
			r.connectionID, r.sensorID, r.runSessionID, r.configSHA256, r.serviceID, r.openedAt, nullableInt64(r.closedAt),
			r.srcIP, r.srcPort, r.dstIP, r.dstPort, r.protocol, r.bytesIn, r.bytesOut, r.requestCount, nullableString(r.closeReason))
		if err != nil {
			return err
		}
	}
	for _, row := range exchanges {
		e := row.event
		queryJSON, _ := json.Marshal(e.QueryFields)
		headerJSON, _ := json.Marshal(e.SanitizedHeaders)
		_, err := tx.Exec(`INSERT INTO exchanges (
request_id,connection_id,timestamp_start_ns,timestamp_end_ns,http_version,method,path,query_metadata_json,
content_type,content_length,request_headers_json,matched_route,classification,response_source,response_sequence,
response_status,request_bytes,response_bytes,request_sha256,response_sha256,request_stream_start,request_stream_length,
response_stream_start,response_stream_length,request_complete,response_complete,write_error)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(request_id) DO UPDATE SET
connection_id=excluded.connection_id,
timestamp_start_ns=excluded.timestamp_start_ns,
timestamp_end_ns=excluded.timestamp_end_ns,
http_version=excluded.http_version,
method=excluded.method,
path=excluded.path,
query_metadata_json=excluded.query_metadata_json,
content_type=excluded.content_type,
content_length=excluded.content_length,
request_headers_json=excluded.request_headers_json,
matched_route=excluded.matched_route,
classification=excluded.classification,
response_source=excluded.response_source,
response_sequence=excluded.response_sequence,
response_status=excluded.response_status,
request_bytes=excluded.request_bytes,
response_bytes=excluded.response_bytes,
request_sha256=excluded.request_sha256,
response_sha256=excluded.response_sha256,
request_stream_start=excluded.request_stream_start,
request_stream_length=excluded.request_stream_length,
response_stream_start=excluded.response_stream_start,
response_stream_length=excluded.response_stream_length,
request_complete=excluded.request_complete,
response_complete=excluded.response_complete,
write_error=excluded.write_error`,
			e.RequestID, e.ConnectionID, e.TimestampStartNS, nullableTimestamp(e.TimestampEndNS), e.HTTPVersion, e.Method, e.RawPath, string(queryJSON),
			e.ContentType, nullableInt64(e.DeclaredContentLength), string(headerJSON), e.MatchedRoute, e.Classification, e.ResponseSource, nullableInt(e.ResponseSequence),
			e.ResponseStatus, e.RequestBytes, e.ResponseBytes, nullableString(row.requestSHA256), nullableString(e.ResponseSHA256), e.RequestStreamStart, e.RequestStreamLength,
			e.ResponseStreamStart, e.ResponseStreamLength, boolInt(e.RequestComplete), boolInt(e.ResponseComplete), nullableString(e.WriteError))
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func nullableInt(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

func nullableInt64(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

func nullableTimestamp(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
