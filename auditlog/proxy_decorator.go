package auditlog

import (
	"net/http"

	"github.com/ory/oathkeeper/proxy"
)

// NewProxyAuditLogDecorator creates new ProxyAuditLogDecorator.
func NewProxyAuditLogDecorator(p proxy.Proxy) *ProxyAuditLogDecorator {
	return &ProxyAuditLogDecorator{
		p: p,
		b: EventBuilder{},
		s: &StdoutSender{},
	}
}

// ProxyAuditLogDecorator is a wrapper for Proxy sctruct with audit logging abilities.
type ProxyAuditLogDecorator struct {
	p proxy.Proxy
	b EventBuilder
	s Sender
}

// RoundTrip performs wrapped structure's RoundTrip and logs this event.
func (d *ProxyAuditLogDecorator) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := d.p.RoundTrip(r)
	go d.logEvent(r, resp, err)
	return resp, err
}

// Director performs wrapped structure's Ditector.
func (d *ProxyAuditLogDecorator) Director(r *http.Request) {
	d.p.Director(r)
}

// logEvent build event and logs it if needed.
func (d *ProxyAuditLogDecorator) logEvent(req *http.Request, resp *http.Response, roundTripError error) {
	if event, err := d.b.Build(req, resp, roundTripError); err == nil {
		d.s.Send(*event)
	}
}
