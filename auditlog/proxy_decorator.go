package auditlog

import (
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
		return nil, errors.New("RoundTrip with nil request")
	}

	body, err := NewReadCloserWithBuffer(req.Body)
	if err != nil {
		return nil, err
	}

	req.Body = body

	// Send request.
	resp, reqErr := d.proxy.RoundTrip(req)

	if reqErr != nil {
		return resp, reqErr
	}

	resp.Body, _ = NewReadCloserWithBuffer(resp.Body)

	// Log event.
	go d.saveEvent(req, resp)

	return resp, nil
}

// Director performs wrapped structure's Director.
func (d *ProxyAuditLogDecorator) Director(r *http.Request) {
	d.proxy.Director(r)
}

func (d *ProxyAuditLogDecorator) saveEvent(req *http.Request, resp *http.Response) {
	for _, b := range d.builders {
		if b.Match(req.URL.String(), req.Method, resp.StatusCode) {
			if event, err := b.Build(req, resp); err == nil {
				for _, s := range d.senders {
					s.Send(*event)
				}
			} else {
				d.logger.WithError(err).Error("Error while building event for audit log")
			}
		}
	}
}
