package controller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type wantGatesOperation struct {
	fields  string
	timeout time.Duration
}

var wantGatesOperations = map[string]wantGatesOperation{
	"group.create":           {"name", 5 * time.Second},
	"group.update":           {"id expected_revision name primary fallbacks probes healthcheck", 5 * time.Second},
	"group.delete":           {"id expected_revision", 5 * time.Second},
	"connection.import":      {"group_id name protocol profile dns allowed_capabilities", 5 * time.Second},
	"connection.update":      {"id expected_revision group_id name profile dns allowed_capabilities", 5 * time.Second},
	"connection.delete":      {"id expected_revision", 5 * time.Second},
	"connection.adapter":     {"protocol", 20 * time.Second},
	"connection.auth-status": {"id", 5 * time.Second},
	"connection.login":       {"id credentials remember", 40 * time.Second},
	"connection.logout":      {"id", 40 * time.Second},
	"connection.restart":     {"id", 40 * time.Second},
	"connection.forget-auth": {"id", 40 * time.Second},
	"rule.create":            {"group_id destination", 5 * time.Second},
	"rule.update":            {"id expected_revision group_id destination", 5 * time.Second},
	"rule.delete":            {"id expected_revision", 5 * time.Second},
	"routing.preview":        {"", 310 * time.Second},
	"routing.apply":          {"plan_id", 310 * time.Second},
	"routing.recover":        {"plan_id", 310 * time.Second},
}

type wantGatesEligibility struct {
	Reason   string `json:"reason"`
	Requires string `json:"requires,omitempty"`
}

type wantGatesPreview struct {
	PlanID               string                                     `json:"plan_id"`
	DesiredRevision      wantGatesRevision                          `json:"desired_revision"`
	Ingress              []string                                   `json:"ingress"`
	Rules                []wantGatesRule                            `json:"rules"`
	Eligibility          map[string]map[string]wantGatesEligibility `json:"eligibility"`
	PreparedConnections  []string                                   `json:"prepared_connections"`
	Unmatched            string                                     `json:"unmatched"`
	Unverified           string                                     `json:"unverified"`
	SessionsMayInterrupt bool                                       `json:"sessions_may_interrupt"`
}

type wantGatesApply struct {
	PlanID                string             `json:"plan_id"`
	State                 string             `json:"state"`
	RunningRevision       *wantGatesRevision `json:"running_revision"`
	Mismatch              bool               `json:"mismatch"`
	NativeCleanupRequired bool               `json:"native_cleanup_required"`
}

type wantGatesAuth struct {
	Authentication string   `json:"authentication"`
	ChallengeID    string   `json:"challenge_id,omitempty"`
	Method         string   `json:"method,omitempty"`
	Methods        []string `json:"methods,omitempty"`
	Prompt         string   `json:"prompt,omitempty"`
	URL            string   `json:"url,omitempty"`
	UserCode       string   `json:"user_code,omitempty"`
	ExpiresAt      *uint64  `json:"expires_at"`
	Remembered     bool     `json:"remembered"`
	SSHForward     *struct {
		LocalHost    string `json:"local_host"`
		LocalPort    int    `json:"local_port"`
		RemoteSocket string `json:"remote_socket"`
	} `json:"ssh_forward,omitempty"`
}

func wantGatesOperationRequest(c *gin.Context, command string, fields string) (map[string]any, error) {
	contentType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || contentType != "application/json" {
		return nil, errWantGatesReply
	}
	body := http.MaxBytesReader(c.Writer, c.Request.Body, wantGatesFrameLimit)
	decoder := json.NewDecoder(body)
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errWantGatesReply
	}
	allowed := strings.Fields(fields)
	request := map[string]any{"command": command}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || !slices.Contains(allowed, name) {
			return nil, errWantGatesReply
		}
		if _, exists := request[name]; exists {
			return nil, errWantGatesReply
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errWantGatesReply
		}
		if name == "expected_revision" {
			var revision string
			if json.Unmarshal(value, &revision) != nil {
				return nil, errWantGatesReply
			}
			number, err := strconv.ParseUint(revision, 10, 64)
			if err != nil {
				return nil, errWantGatesReply
			}
			request[name] = number
		} else {
			request[name] = value
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, errWantGatesReply
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errWantGatesReply
	}
	return request, nil
}

func publicWantGatesError(command, detail string) (int, string) {
	switch {
	case strings.Contains(detail, "revision conflict"):
		return http.StatusConflict, "This object changed. Refresh its current settings and submit again."
	case strings.Contains(detail, "routing operation in progress"):
		return http.StatusConflict, "A routing operation is in progress. Refresh routing status when it finishes."
	case strings.Contains(detail, "drift"), strings.Contains(detail, "changed since preview"), strings.Contains(detail, "create a new preview"), strings.Contains(detail, "preview again"):
		return http.StatusConflict, "The applied context changed. Inspect status and create a new preview."
	case strings.Contains(detail, "recovery"), strings.Contains(detail, "recover before"):
		return http.StatusConflict, "Routing needs inspection or recovery. Refresh status before another apply."
	case strings.Contains(detail, "is referenced"):
		return http.StatusConflict, "This object is in use. Update its group, rules or connections before removing it."
	case strings.Contains(detail, "name already exists"):
		return http.StatusBadRequest, "This name is already in use."
	case strings.Contains(detail, "must not belong"), strings.Contains(detail, "same group"):
		return http.StatusBadRequest, "Select connections that belong to this company group."
	case strings.Contains(detail, "destination") && (command == "rule.create" || command == "rule.update"):
		return http.StatusBadRequest, "Check the destination and its group. Existing rules may conflict."
	case strings.Contains(detail, "native authentication requires"):
		return http.StatusConflict, "Preview and apply the current connection profile before opening native authentication."
	case strings.Contains(detail, "challenge"), strings.Contains(detail, "expired"):
		return http.StatusConflict, "Refresh the authentication challenge and check the required fields."
	case strings.Contains(detail, "runtime unavailable"):
		return http.StatusServiceUnavailable, "The native service is unavailable."
	case strings.HasPrefix(command, "routing."):
		return http.StatusBadRequest, "The routing operation did not complete. Inspect routing status and the required probes."
	default:
		return http.StatusBadRequest, "Want Gates rejected the settings. Check the supplied values and adapter requirements."
	}
}

func wantGatesOperationData(command string, data json.RawMessage) (any, error) {
	switch command {
	case "routing.preview":
		var view wantGatesPreview
		err := json.Unmarshal(data, &view)
		return view, err
	case "routing.apply", "routing.recover":
		var view wantGatesApply
		err := json.Unmarshal(data, &view)
		return view, err
	case "connection.adapter":
		var view struct {
			Available bool   `json:"available"`
			Reason    string `json:"reason"`
		}
		err := json.Unmarshal(data, &view)
		return view, err
	case "connection.login", "connection.auth-status":
		var view wantGatesAuth
		if err := json.Unmarshal(data, &view); err != nil {
			return nil, err
		}
		if link, err := url.Parse(view.URL); err != nil || link.Scheme != "https" || link.Hostname() == "" || link.User != nil {
			view.URL = ""
		}
		if relay := view.SSHForward; relay != nil && (relay.LocalHost != "127.0.0.1" || relay.LocalPort != 8020 ||
			!filepath.IsAbs(relay.RemoteSocket) || filepath.Clean(relay.RemoteSocket) != relay.RemoteSocket ||
			strings.IndexFunc(relay.RemoteSocket, func(r rune) bool {
				return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-", r))
			}) >= 0) {
			view.SSHForward = nil
		}
		return view, nil
	default:
		return nil, nil
	}
}

func wantGatesMutate(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	command := c.Param("operation")
	operation, allowed := wantGatesOperations[command]
	if !allowed {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "msg": "Unsupported Want Gates operation."})
		return
	}
	request, err := wantGatesOperationRequest(c, command, operation.fields)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "Invalid Want Gates request."})
		return
	}
	socket := wantGatesSocketPath()
	if !filepath.IsAbs(socket) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "msg": "Want Gates control socket must have an absolute path."})
		return
	}
	if operation.timeout >= 30*time.Second {
		deadline := time.Now().Add(operation.timeout + 5*time.Second)
		if err := http.NewResponseController(c.Writer).SetWriteDeadline(deadline); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "msg": "The panel cannot wait for this routing operation."})
			return
		}
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), operation.timeout)
	defer cancel()
	reply, err := wantGatesExchange(ctx, socket, request)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "msg": "The service reply could not be confirmed. Refresh status before retrying."})
		return
	}
	if reply.Error != "" {
		status, message := publicWantGatesError(command, reply.Error)
		c.JSON(status, gin.H{"success": false, "msg": message})
		return
	}
	data, err := wantGatesOperationData(command, reply.Data)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "msg": "The service reply is invalid. Refresh status before retrying."})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "obj": data})
}
