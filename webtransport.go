package webtransport

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

const (
	webTransportDraftOfferHeaderKey = "Sec-Webtransport-Http3-Draft02"
	webTransportDraftHeaderKey      = "Sec-Webtransport-Http3-Draft"
	webTransportDraftHeaderValue    = "draft02"
)

const (
	webTransportFrameType     = 0x41
	webTransportUniStreamType = 0x54
)

const settingsEnableWebtransport = 0x2b603742

const protocolHeader = "webtransport"


func (s *sessionManager) Upgrade(w http.ResponseWriter, r *http.Request) (Session, error) {
	if r.Method != http.MethodConnect {
		return nil, fmt.Errorf("expected CONNECT request, got %s", r.Method)
	}
	if r.Proto != protocolHeader {
		return nil, fmt.Errorf("unexpected protocol: %s", r.Proto)
	}
	if v, ok := r.Header[webTransportDraftOfferHeaderKey]; !ok || len(v) != 1 || v[0] != "1" {
		return nil, fmt.Errorf("missing or invalid %s header", webTransportDraftOfferHeaderKey)
	}
	
	w.Header().Add(webTransportDraftHeaderKey, webTransportDraftHeaderValue)
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()

	httpStreamer, ok := r.Body.(http3.HTTPStreamer)
	if !ok {
		return nil, errors.New("failed to take over HTTP stream")
	}
	str := httpStreamer.HTTPStream()
	sID := sessionID(str.StreamID())

	hijacker, ok := w.(http3.Hijacker)
	if !ok { // should never happen, unless quic-go changed the API
		return nil, errors.New("failed to hijack")
	}
	return s.AddSession(
		hijacker.StreamCreator(),
		sID,
		r.Body.(http3.HTTPStreamer).HTTPStream(),
	), nil
}
