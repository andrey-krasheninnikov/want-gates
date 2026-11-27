package controller

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWantGatesSnapshotKeepsRevisionAndOmitsPrivateFields(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const revision = uint64(18446744073709551614)
	const secret = "synthetic-profile-secret"
	replies := []struct {
		command string
		offset  uint64
		body    string
	}{
		{"routing.status", 0, `{"data":{"desired_revision":18446744073709551614,"observed_digest":"observed-fixture","health_error":"panel_drift","last_observation":{"state":"unapplied","unreviewed":"synthetic-profile-secret"}}}`},
		{"group.list", 0, `{"data":[{"id":"g1","revision":1,"name":"Company"}],"list_revision":18446744073709551614,"next_offset":1}`},
		{"group.list", 1, `{"data":[{"id":"g2","revision":2,"name":"Reserve"}],"list_revision":18446744073709551614}`},
		{"connection.list", 0, `{"data":[{"id":"c3","revision":18446744073709551614,"group_id":"g1","name":"VLESS path","profile":"synthetic-profile-secret","verification":{"capabilities":{"tcp_ipv4":{"state":"verified","reason":"verified","detail":"synthetic-profile-secret"}}}}],"list_revision":18446744073709551614}`},
		{"rule.list", 0, `{"data":[],"list_revision":18446744073709551614}`},
	}
	served := make(chan error, 1)
	go func() {
		for _, page := range replies {
			conn, err := listener.Accept()
			if err != nil {
				served <- err
				return
			}
			var request struct {
				Version        int     `json:"api_version"`
				Command        string  `json:"command"`
				ListRevision   *uint64 `json:"list_revision"`
				Offset         uint64  `json:"offset"`
				Summary        bool    `json:"summary"`
				ObservedDigest string  `json:"observed_digest"`
			}
			err = json.NewDecoder(conn).Decode(&request)
			if err == nil && (request.Version != 1 || request.Command != page.command || request.Offset != page.offset ||
				page.command != "routing.status" && (request.ListRevision == nil || *request.ListRevision != revision) ||
				page.command == "routing.status" && !request.Summary ||
				page.command == "group.list" && request.ObservedDigest != "observed-fixture") {
				err = errWantGatesReply
			}
			if err == nil {
				_, err = conn.Write([]byte(`{"api_version":1,` + page.body[1:] + "\n"))
			}
			conn.Close()
			if err != nil {
				served <- err
				return
			}
		}
		served <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	state, err := loadWantGatesSnapshot(ctx, socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if len(state.Groups) != 2 || len(state.Connections) != 1 || state.Connections[0].Verification.Capabilities["tcp_ipv4"].State != "verified" {
		t.Fatal("expected paged gateway status")
	}
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), secret) || strings.Contains(string(body), "observed-fixture") || !strings.Contains(string(body), `"revision":"18446744073709551614"`) {
		t.Fatal("private status or inaccurate revision in response")
	}
}
