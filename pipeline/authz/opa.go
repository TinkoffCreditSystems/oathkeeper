package authz

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"text/template"

	"github.com/ory/x/httpx"
	"github.com/pkg/errors"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/helper"
	"github.com/ory/oathkeeper/pipeline"
	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/oathkeeper/x"
)

// AuthorizerOPAConfiguration represents a configuration for the opa authorizer.
type AuthorizerOPAConfiguration struct {
	Endpoint string      `json:"endpoint"`
	Headers  http.Header `json:"headers"`
	Payload  string      `json:"payload"`
}

// PayloadTemplateID returns a string with which to associate the payload template.
func (c *AuthorizerOPAConfiguration) PayloadTemplateID() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(c.Payload)))
}

type opaResponsePayload struct {
	Result struct {
		Allow bool   `json:"allow"`
		Deny  string `json:"deny"`
	} `json:"result"`
}

func (p opaResponsePayload) Forbidden() bool {
	return p.Result.Deny != "" || !p.Result.Allow
}

var _ Authorizer = (*AuthorizerOPA)(nil)

// AuthorizerOPA implements the Authorizer interface.
type AuthorizerOPA struct {
	c configuration.Provider

	client *http.Client
	t      *template.Template
}

// NewAuthorizerOPA creates a new AuthorizerOPA.
func NewAuthorizerOPA(c configuration.Provider) *AuthorizerOPA {
	return &AuthorizerOPA{
		c:      c,
		client: httpx.NewResilientClientLatencyToleranceSmall(nil),
		t:      x.NewTemplate("opa"),
	}
}

// GetID implements the Authorizer interface.
func (a *AuthorizerOPA) GetID() string {
	return "opa"
}

// Authorize implements the Authorizer interface.
func (a *AuthorizerOPA) Authorize(_ *http.Request, session *authn.AuthenticationSession, config json.RawMessage, _ pipeline.Rule) error {
	c, err := a.Config(config)
	if err != nil {
		return err
	}

	templateID := c.PayloadTemplateID()
	t := a.t.Lookup(templateID)
	if t == nil {
		var err error
		t, err = a.t.New(templateID).Parse(c.Payload)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	var body bytes.Buffer
	if err := t.Execute(&body, session); err != nil {
		return errors.WithStack(err)
	}

	req, err := http.NewRequest("POST", c.Endpoint, &body)
	if err != nil {
		return errors.WithStack(err)
	}
	for header, values := range c.Headers {
		for i := range values {
			req.Header.Add(header, values[i])
		}
	}
	if len(req.Header.Values("Content-Type")) == 0 {
		req.Header.Add("Content-Type", "application/json")
	}

	res, err := a.client.Do(req)
	if err != nil {
		return errors.WithStack(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return errors.Errorf("expected status code %d but got %d", http.StatusOK, res.StatusCode)
	}

	var respPayload opaResponsePayload
	if err := json.NewDecoder(res.Body).Decode(&respPayload); err != nil {
		return errors.WithStack(err)
	}

	if respPayload.Forbidden() {
		err := helper.ErrForbidden
		if respPayload.Result.Deny != "" {
			err = err.WithReason(respPayload.Result.Deny)
		}

		return errors.WithStack(err)
	}

	return nil
}

// Validate implements the Authorizer interface.
func (a *AuthorizerOPA) Validate(config json.RawMessage) error {
	if !a.c.AuthorizerIsEnabled(a.GetID()) {
		return NewErrAuthorizerNotEnabled(a)
	}

	_, err := a.Config(config)
	return err
}

// Config merges config and the authorizer's configuration and validates the
// resulting configuration. It reports an error if the configuration is invalid.
func (a *AuthorizerOPA) Config(config json.RawMessage) (*AuthorizerOPAConfiguration, error) {
	var c AuthorizerOPAConfiguration
	if err := a.c.AuthorizerConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrAuthorizerMisconfigured(a, err)
	}

	return &c, nil
}
