package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestWantGatesOperationRejectsUnlistedFieldsAndKeepsExactRevision(t *testing.T) {
	fields := wantGatesOperations["group.update"].fields
	read := func(body string) (map[string]any, error) {
		context, _ := gin.CreateTestContext(httptest.NewRecorder())
		context.Request = httptest.NewRequest("POST", "/", strings.NewReader(body))
		context.Request.Header.Set("Content-Type", "application/json")
		return wantGatesOperationRequest(context, "group.update", fields)
	}
	for _, body := range []string{
		`{"api_version":2}`,
		`{"command":"panel.configure"}`,
		`{"name":"a","name":"b"}`,
		`{"expected_revision":2}`,
		`{"id":"g1","name":"Group"}`,
		`{"name":"a"} {"name":"b"}`,
	} {
		if _, err := read(body); err == nil {
			t.Fatal("invalid operation body was accepted")
		}
	}
	request, err := read(`{"id":"g1","expected_revision":"18446744073709551615","name":"Group"}`)
	if err != nil || request["expected_revision"] != uint64(18446744073709551615) {
		t.Fatal("operation lost the submitted revision")
	}
}

func TestWantGatesMapsUnconfirmedResults(t *testing.T) {
	for _, example := range []struct {
		command string
		detail  string
		status  int
		message string
	}{
		{"connection.login", "native runtime transport unavailable", http.StatusServiceUnavailable, "could not be confirmed"},
		{"connection.update", "configuration saved but durability is uncertain", http.StatusServiceUnavailable, "may be saved"},
		{"connection.update", "configuration saved; unused profile cleanup failed", http.StatusConflict, "was saved"},
		{"connection.login", "could not persist credential record", http.StatusConflict, "Check sign-in"},
		{"routing.recover", "intervening panel edits prevent restoration; retain state and reconcile manually", http.StatusConflict, "manually"},
	} {
		status, message := publicWantGatesError(example.command, example.detail)
		if status != example.status || !strings.Contains(message, example.message) {
			t.Fatalf("incorrect result status or message for %s", example.command)
		}
	}
	for _, data := range []string{
		`{"plan_id":"test"}`,
		`{"plan_id":"test","state":"applied","running_revision":3}`,
		`{"plan_id":"test","state":"applied","mismatch":false}`,
	} {
		if _, err := wantGatesOperationData("routing.apply", json.RawMessage(data)); err == nil {
			t.Fatal("accepted an incomplete apply result")
		}
	}
}

func TestWantGatesAuthReplyProjectsOnlyTheCurrentChallenge(t *testing.T) {
	body := json.RawMessage(`{
		"authentication":"browser_required",
		"method":"browser",
		"url":"file:///tmp/fixture",
		"user_code":"DEVICE-TEST",
		"private_key":"synthetic-secret",
		"credentials":{"password":"synthetic-secret"},
		"ssh_forward":{"local_host":"127.0.0.1","local_port":8020,"remote_socket":"relative"}
	}`)
	projected, err := wantGatesOperationData("connection.auth-status", body)
	if err != nil {
		t.Fatal(err)
	}
	view := projected.(wantGatesAuth)
	if view.URL != "" || view.SSHForward != nil || view.UserCode != "DEVICE-TEST" {
		t.Fatal("unexpected challenge projection")
	}
	result, err := json.Marshal(view)
	if err != nil || strings.Contains(string(result), "synthetic-secret") {
		t.Fatal("private authentication field in response")
	}
}
