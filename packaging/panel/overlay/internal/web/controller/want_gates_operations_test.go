package controller

import (
	"encoding/json"
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
