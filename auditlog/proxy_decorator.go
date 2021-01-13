package auditlog

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/proxy"
	"github.com/ory/x/logrusx"
	"github.com/pkg/errors"
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
	bs, err := DeserializeEventBuildersFromFiles(config.AuditLogConfigPath())
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
	if req == nil {
		d.logger.Error("Request is nil")

		return nil, errors.New("RoundTrip with nil request")
	}

	// Copy the request body before the request is sent further.
	var reqBodyCopy io.ReadCloser
	req.Body, reqBodyCopy = copyBody(req.Body, d.logger)

	// Send request.
	resp, err := d.proxy.RoundTrip(req)

	// Deep copy request.
	reqCopy := req.Clone(req.Context())
	reqCopy.Body = reqBodyCopy

	// Deep copy response.
	respCopy := new(http.Response)
	if resp != nil {
		*respCopy = *resp
		resp.Body, respCopy.Body = copyBody(resp.Body, d.logger)
	}

	// Log event.
	go d.saveEvent(reqCopy, respCopy, err)

	return resp, err
}

// Director performs wrapped structure's Director.
func (d *ProxyAuditLogDecorator) Director(r *http.Request) {
	d.proxy.Director(r)
}

func copyBody(rc io.Reader, logger *logrusx.Logger) (a, b io.ReadCloser) {
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

func (d *ProxyAuditLogDecorator) saveEvent(req *http.Request, resp *http.Response, roundTripError error) {
	for _, b := range d.builders {
		if b.Match(req.URL.String(), req.Method) {
			if event, err := b.Build(req, resp, roundTripError); err == nil {
				for _, s := range d.senders {
					s.Send(*event)
				}
			} else {
				d.logger.WithError(err).Error("Error while building event for audit log")
			}
		}
	}
}
