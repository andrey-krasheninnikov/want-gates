package controller

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

const wantGatesSocket = "/run/wgates/control.sock"
const wantGatesFrameLimit = 4 * 1024 * 1024

type wantGatesReply struct {
	Version      int             `json:"api_version"`
	Data         json.RawMessage `json:"data"`
	Error        string          `json:"error"`
	ListRevision *uint64         `json:"list_revision"`
	NextOffset   *uint64         `json:"next_offset"`
}

type wantGatesRevision uint64

func (revision *wantGatesRevision) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, (*uint64)(revision))
}

func (revision wantGatesRevision) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(strconv.FormatUint(uint64(revision), 10))), nil
}

type wantGatesObject struct {
	ID       string            `json:"id"`
	Revision wantGatesRevision `json:"revision"`
}

type wantGatesProbe struct {
	URL            string  `json:"url,omitempty"`
	ExpectedStatus *uint16 `json:"expected_status,omitempty"`
	Server         string  `json:"server,omitempty"`
	QueryName      string  `json:"query_name,omitempty"`
	QueryType      string  `json:"query_type,omitempty"`
}

type wantGatesHealthcheck struct {
	Target               string   `json:"target"`
	RequiredCapabilities []string `json:"required_capabilities"`
	Interval             uint64   `json:"interval_seconds"`
	Timeout              uint64   `json:"timeout_seconds"`
	FailureThreshold     uint64   `json:"failure_threshold"`
	RecoveryThreshold    uint64   `json:"recovery_threshold"`
	ExpectedStatus       *uint16  `json:"expected_status"`
	CACertificate        *string  `json:"ca_pem"`
	TCPRequest           *string  `json:"send_hex"`
	TCPReply             *string  `json:"expect_hex"`
}

type wantGatesGroup struct {
	wantGatesObject
	Name      string             `json:"name"`
	Primary   *string            `json:"primary"`
	Fallbacks []string           `json:"fallbacks"`
	Selected  *wantGatesSelected `json:"last_observed_selection"`
	Probes    *struct {
		TCPv4 *wantGatesProbe `json:"tcp_ipv4,omitempty"`
		UDPv4 *wantGatesProbe `json:"udp_ipv4,omitempty"`
		TCPv6 *wantGatesProbe `json:"tcp_ipv6,omitempty"`
		UDPv6 *wantGatesProbe `json:"udp_ipv6,omitempty"`
		DNS   *wantGatesProbe `json:"dns,omitempty"`
	} `json:"probes"`
	Healthcheck *wantGatesHealthcheck `json:"healthcheck"`
}

type wantGatesCheck struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

type wantGatesHealth struct {
	wantGatesCheck
	Eligible   bool   `json:"eligible"`
	ObservedAt uint64 `json:"observed_at"`
}

type wantGatesVerification struct {
	Capabilities map[string]wantGatesCheck `json:"capabilities"`
	DNS          wantGatesCheck            `json:"dns"`
	ObservedAt   *uint64                   `json:"observed_at"`
}

type wantGatesConnection struct {
	wantGatesObject
	Name                string                `json:"name"`
	GroupID             string                `json:"group_id"`
	Protocol            string                `json:"protocol"`
	DNS                 *string               `json:"dns"`
	AllowedCapabilities []string              `json:"allowed_capabilities"`
	Capabilities        []string              `json:"capabilities"`
	Authentication      string                `json:"authentication"`
	Runtime             string                `json:"runtime"`
	RuntimeReason       string                `json:"runtime_reason"`
	Health              *wantGatesHealth      `json:"health"`
	Verification        wantGatesVerification `json:"verification"`
}

type wantGatesRule struct {
	wantGatesObject
	GroupID     string `json:"group_id"`
	Destination string `json:"destination"`
}

type wantGatesSelected struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
}

type wantGatesRouting struct {
	DesiredRevision wantGatesRevision `json:"desired_revision"`
	Busy            bool              `json:"busy"`
	Recovery        bool              `json:"recovery_required"`
	HealthError     *string           `json:"health_error"`
	RecoveryPlanID  *string           `json:"recovery_plan_id"`
	Last            struct {
		State           string             `json:"state"`
		RunningRevision *wantGatesRevision `json:"running_revision"`
		Mismatch        bool               `json:"mismatch"`
		ObservedAt      *uint64            `json:"observed_at"`
	} `json:"last_observation"`
}

type wantGatesSnapshot struct {
	Routing     wantGatesRouting      `json:"routing"`
	Groups      []wantGatesGroup      `json:"groups"`
	Connections []wantGatesConnection `json:"connections"`
	Rules       []wantGatesRule       `json:"rules"`
}

var errWantGatesReply = errors.New("invalid Want Gates service response")
var errWantGatesChanged = errors.New("Want Gates configuration changed")

func wantGatesExchange(ctx context.Context, socket string, request map[string]any) (wantGatesReply, error) {
	var reply wantGatesReply
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return reply, err
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		return reply, errWantGatesReply
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return reply, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	request["api_version"] = 1
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return reply, err
	}
	reader := bufio.NewReader(io.LimitReader(conn, wantGatesFrameLimit+1))
	frame, err := reader.ReadBytes('\n')
	if err != nil || len(frame) > wantGatesFrameLimit+1 || json.Unmarshal(frame, &reply) != nil || reply.Version != 1 || len(reply.Data) == 0 && reply.Error == "" {
		return wantGatesReply{}, errWantGatesReply
	}
	return reply, nil
}

func wantGatesList[T any](ctx context.Context, socket, command string, revision uint64, observedDigest *string) ([]T, error) {
	items := make([]T, 0)
	var offset uint64
	for {
		request := map[string]any{"command": command, "list_revision": revision, "offset": offset, "page_size": 1000}
		if observedDigest != nil {
			request["observed_digest"] = *observedDigest
		}
		reply, err := wantGatesExchange(ctx, socket, request)
		if err != nil {
			return nil, err
		}
		if reply.Error == "configuration changed during listing; retry" || reply.Error == "routing observation changed during listing; retry" {
			return nil, errWantGatesChanged
		}
		var page []T
		if reply.Error != "" || reply.ListRevision == nil || *reply.ListRevision != revision ||
			json.Unmarshal(reply.Data, &page) != nil || page == nil {
			return nil, errWantGatesReply
		}
		items = append(items, page...)
		if reply.NextOffset == nil {
			return items, nil
		}
		if *reply.NextOffset <= offset || *reply.NextOffset-offset != uint64(len(page)) {
			return nil, errWantGatesReply
		}
		offset = *reply.NextOffset
	}
}

type wantGatesSummary struct {
	wantGatesRouting
	ObservedDigest *string `json:"observed_digest"`
}

func readWantGatesSummary(ctx context.Context, socket string) (wantGatesSummary, error) {
	var routing wantGatesSummary
	reply, err := wantGatesExchange(ctx, socket, map[string]any{"command": "routing.status", "summary": true})
	if err != nil {
		return routing, err
	}
	if reply.Error != "" || json.Unmarshal(reply.Data, &routing) != nil || routing.Last.State == "" {
		return routing, errWantGatesReply
	}
	return routing, nil
}

func loadWantGatesSnapshot(ctx context.Context, socket string) (wantGatesSnapshot, error) {
	var result wantGatesSnapshot
	routing, err := readWantGatesSummary(ctx, socket)
	if err != nil {
		return result, err
	}
	result.Routing = routing.wantGatesRouting
	revision := uint64(routing.DesiredRevision)
	result.Groups, err = wantGatesList[wantGatesGroup](ctx, socket, "group.list", revision, routing.ObservedDigest)
	if err != nil {
		return result, err
	}
	result.Connections, err = wantGatesList[wantGatesConnection](ctx, socket, "connection.list", revision, routing.ObservedDigest)
	if err != nil {
		return result, err
	}
	result.Rules, err = wantGatesList[wantGatesRule](ctx, socket, "rule.list", revision, nil)
	if err != nil {
		return result, err
	}
	latest, err := readWantGatesSummary(ctx, socket)
	if err != nil {
		return result, err
	}
	if !reflect.DeepEqual(routing, latest) {
		return wantGatesSnapshot{}, errWantGatesChanged
	}
	if routing.ObservedDigest == nil {
		for index := range result.Connections {
			connection := &result.Connections[index]
			connection.Runtime = "unavailable"
			connection.RuntimeReason = "observation_unavailable"
			connection.Capabilities = nil
		}
	}
	return result, nil
}

func wantGatesSocketPath() string {
	if custom := os.Getenv("WGATES_CONTROL_SOCKET"); custom != "" {
		return custom
	}
	return wantGatesSocket
}

func wantGatesStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()
	socket := wantGatesSocketPath()
	if !filepath.IsAbs(socket) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "msg": "Want Gates control socket must have an absolute path."})
		return
	}
	state, err := loadWantGatesSnapshot(ctx, socket)
	if errors.Is(err, errWantGatesChanged) {
		c.JSON(http.StatusConflict, gin.H{"success": false, "msg": "Configuration or routing observation changed while loading. Refresh Want Gates status."})
		return
	}
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "msg": "Want Gates service is unavailable. Check the local service and socket access."})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "obj": state})
}
