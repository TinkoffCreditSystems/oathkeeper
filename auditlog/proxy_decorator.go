package auditlog

import (
	"github.com/ory/x/logrusx"
	"net/http"

	"github.com/ory/oathkeeper/proxy"
)

type RoundTripper interface {
	RoundTrip(r *http.Request) (*http.Response, error)
	Director(r *http.Request)
}

// NewProxyAuditLogDecorator creates new ProxyAuditLogDecorator.
func NewProxyAuditLogDecorator(proxy proxy.Proxy, configPath string, logger *logrusx.Logger) *ProxyAuditLogDecorator {
	ValidateSchema(configPath, logger)

	return &ProxyAuditLogDecorator{
		p: proxy,
		b: EventBuilder{},
		s: &StdoutSender{},
		l: logger,
	}
}

// ProxyAuditLogDecorator is a wrapper for Proxy struct with audit logging abilities.
type ProxyAuditLogDecorator struct {
	p proxy.Proxy
	b EventBuilder
	s Sender
	l *logrusx.Logger
}

// RoundTrip performs wrapped structure's RoundTrip and logs this event.
func (d *ProxyAuditLogDecorator) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := d.p.RoundTrip(r)
	go d.logEvent(r, resp, err)
	return resp, err
}

// Director performs wrapped structure's Director.
func (d *ProxyAuditLogDecorator) Director(r *http.Request) {
	d.p.Director(r)
}

// logEvent build event and logs it if needed.
func (d *ProxyAuditLogDecorator) logEvent(req *http.Request, resp *http.Response, roundTripError error) {
	if event, err := d.b.Build(req, resp, roundTripError); err == nil {
		d.s.Send(*event)
	}
}
