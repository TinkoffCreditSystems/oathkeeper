package auditlog

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/proxy"
	"github.com/ory/x/logrusx"
)

// RoundTripper interface is implemented by the Proxy structure and it's decorators.
type RoundTripper interface {
	RoundTrip(r *http.Request) (*http.Response, error)
	Director(r *http.Request)
}

// ProxyAuditLogDecorator is a wrapper for Proxy struct with audit logging abilities.
type ProxyAuditLogDecorator struct {
	p proxy.Proxy
	b []EventBuilder
	s []Sender
	l *logrusx.Logger
}

// NewProxyAuditLogDecorator creates new ProxyAuditLogDecorator.
func NewProxyAuditLogDecorator(proxy proxy.Proxy, config configuration.Provider, logger *logrusx.Logger) *ProxyAuditLogDecorator {
	d := &ProxyAuditLogDecorator{
		p: proxy,
		b: DeserializeEventBuilders(config.AuditLogConfigPath(), config.AuditLogSchemaPath(), logger),
		s: make([]Sender, 0),
		l: logger,
	}

	d.s = append(d.s, &StdoutSender{l: logger})
	if config.AuditLogKafkaEnabled() {
		d.s = append(d.s, &KafkaSender{})
	}

	return d
}

// RoundTrip performs wrapped structure's RoundTrip and logs request's event.
func (d *ProxyAuditLogDecorator) RoundTrip(req *http.Request) (*http.Response, error) {
	// Copy request body.
	var reqBodyCopy io.ReadCloser = nil
	if req != nil {
		req.Body, reqBodyCopy = copyBody(req.Body, d.l)
	}

	// Send request.
	resp, err := d.p.RoundTrip(req)

	// Copy response body.
	var respBodyCopy io.ReadCloser = nil
	if resp != nil {
		resp.Body, respBodyCopy = copyBody(resp.Body, d.l)
	}

	// Log event.
	go d.saveEvent(req, resp, reqBodyCopy, respBodyCopy, err)
	return resp, err
}

func copyBody(rc io.ReadCloser, logger *logrusx.Logger) (a, b io.ReadCloser) {
	if rc != nil {
		body, err := ioutil.ReadAll(rc)
		if err != nil {
			logger.Error("Error reading request body in RoundTrip")
		}
		a = ioutil.NopCloser(bytes.NewReader(body))
		b = ioutil.NopCloser(bytes.NewReader(body))
	}
	return a, b
}

// Director performs wrapped structure's Director.
func (d *ProxyAuditLogDecorator) Director(r *http.Request) {
	d.p.Director(r)
}

// saveEvent builds event and logs it if needed.
func (d *ProxyAuditLogDecorator) saveEvent(reqImmutable *http.Request, respImmutable *http.Response,
	reqBodyCopy, respBodyCopy io.ReadCloser, roundTripError error) {

	if reqImmutable == nil {
		d.l.Error("Request struct is nil")
		return
	}

	// Deep copy request & response.
	req := reqImmutable.Clone(reqImmutable.Context())
	req.Body = reqBodyCopy
	resp := new(http.Response)
	*resp = *respImmutable
	resp.Body = respBodyCopy

	// Log event.
	for _, b := range d.b {
		if b.Match(req.URL.String(), req.Method) {
			if event, err := b.Build(req, resp, roundTripError); err == nil {
				for _, s := range d.s {
					s.Send(*event)
				}
			} else {
				d.l.WithFields(log.Fields{"error": err}).Error("Error while building event for audit log")
			}
		}
	}
}
