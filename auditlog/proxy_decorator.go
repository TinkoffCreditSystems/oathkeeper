package auditlog

import (
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/ory/oathkeeper/proxy"
	"github.com/ory/x/logrusx"
)

// RoundTripper interface is implemented by the Proxy structure and it's decorators.
type RoundTripper interface {
	RoundTrip(r *http.Request) (*http.Response, error)
	Director(r *http.Request)
}

// NewProxyAuditLogDecorator creates new ProxyAuditLogDecorator.
func NewProxyAuditLogDecorator(proxy proxy.Proxy, configPath string, logger *logrusx.Logger) *ProxyAuditLogDecorator {
	return &ProxyAuditLogDecorator{
		p: proxy,
		b: DeserializeEventBuilders(configPath, logger),
		s: &StdoutSender{},
		l: logger,
	}
}

// ProxyAuditLogDecorator is a wrapper for Proxy struct with audit logging abilities.
type ProxyAuditLogDecorator struct {
	p proxy.Proxy
	b []EventBuilder
	s Sender
	l *logrusx.Logger
}

// RoundTrip performs wrapped structure's RoundTrip and logs this event.
func (d *ProxyAuditLogDecorator) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := d.p.RoundTrip(r)
	go d.saveEvent(r, resp, err)
	return resp, err
}

// Director performs wrapped structure's Director.
func (d *ProxyAuditLogDecorator) Director(r *http.Request) {
	d.p.Director(r)
}

// saveEvent builds event and logs it if needed.
func (d *ProxyAuditLogDecorator) saveEvent(req *http.Request, resp *http.Response, roundTripError error) {
	if req == nil {
		d.l.Error("Request struct is nil")
		return
	}

	for _, b := range d.b {
		if b.Match(req.URL.String(), req.Method) {
			if event, err := b.Build(req, resp, roundTripError); err == nil {
				d.s.Send(*event)
			} else {
				d.l.WithFields(log.Fields{"error": err}).Error("Error while reading Audit Log configuration")
			}
		}
	}
}
