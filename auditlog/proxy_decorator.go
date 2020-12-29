package auditlog

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/ory/x/logrusx"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/proxy"
)

// RoundTripper interface is implemented by the Proxy structure and it's decorators.
type RoundTripper interface {
	RoundTrip(r *http.Request) (*http.Response, error)
	Director(r *http.Request)
}

// ProxyAuditLogDecorator is a wrapper for Proxy struct with audit logging abilities.
type ProxyAuditLogDecorator struct {
	proxy    RoundTripper
	builders []EventBuilder
	senders  []Sender
	logger   *logrusx.Logger
}

func NewProxyAuditLogDecoratorFromFile(proxy *proxy.Proxy, config configuration.Provider,
	logger *logrusx.Logger) (*ProxyAuditLogDecorator, error) {
	bs, err := DeserializeEventBuildersFromFiles(config.AuditLogConfigPath(), config.AuditLogSchemaPath())
	if err != nil {
		return nil, err
	}
	return NewProxyAuditLogDecoratorFromEventBuilders(proxy, config, logger, bs)
}

func NewProxyAuditLogDecoratorFromEventBuilders(proxy *proxy.Proxy, config configuration.Provider,
	logger *logrusx.Logger, bs []EventBuilder) (*ProxyAuditLogDecorator, error) {
	d := &ProxyAuditLogDecorator{
		proxy:    proxy,
		builders: bs,
		senders:  make([]Sender, 0),
		logger:   logger,
	}

	d.senders = append(d.senders, &StdoutSender{l: logger})
	if config.AuditLogKafkaEnabled() {
		d.senders = append(d.senders, &KafkaSender{})
	}

	return d, nil
}

// RoundTrip performs wrapped structure's RoundTrip and logs request's event.
func (d *ProxyAuditLogDecorator) RoundTrip(req *http.Request) (*http.Response, error) {
	// Copy request body.
	var reqBodyCopy io.ReadCloser = nil
	if req != nil {
		req.Body, reqBodyCopy = copyBody(req.Body, d.logger)
	}

	// Send request.
	resp, err := d.proxy.RoundTrip(req)

	// Copy response body.
	var respBodyCopy io.ReadCloser = nil
	if resp != nil {
		resp.Body, respBodyCopy = copyBody(resp.Body, d.logger)
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
	d.proxy.Director(r)
}

func (d *ProxyAuditLogDecorator) saveEvent(reqImmutable *http.Request, respImmutable *http.Response,
	reqBodyCopy, respBodyCopy io.ReadCloser, roundTripError error) {

	if reqImmutable == nil {
		d.logger.Error("Request struct is nil")
		return
	}

	// Deep copy request & response.
	req := reqImmutable.Clone(reqImmutable.Context())
	req.Body = reqBodyCopy
	resp := new(http.Response)
	*resp = *respImmutable
	resp.Body = respBodyCopy

	// Log event.
	for _, b := range d.builders {
		if b.Match(req.URL.String(), req.Method) {
			if event, err := b.Build(req, resp, roundTripError); err == nil {
				for _, s := range d.senders {
					s.Send(*event)
				}
			} else {
				d.logger.WithFields(log.Fields{"error": err}).Error("Error while building event for audit log")
			}
		}
	}
}
