package authz

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/google/go-jsonnet"
	"io/ioutil"
	"net/http"
	"strings"
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
	Endpoint string `json:"endpoint"`
	Payload  string `json:"payload"`
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

type OpaInput struct {
	*authn.AuthenticationSession
	UpstreamRequest map[string]interface{} `json:"upstream_request"`
}

type OpaRequest struct {
	Input *OpaInput `json:"input"`
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
	vm     *jsonnet.VM
}

// NewAuthorizerOPA creates a new AuthorizerOPA.
func NewAuthorizerOPA(c configuration.Provider) *AuthorizerOPA {
	return &AuthorizerOPA{
		c:      c,
		client: httpx.NewResilientClientLatencyToleranceSmall(nil),
		t:      x.NewTemplate("opa"),
		vm:     jsonnet.MakeVM(),
	}
}

// GetID implements the Authorizer interface.
func (a *AuthorizerOPA) GetID() string {
	return "opa"
}

// Authorize implements the Authorizer interface.
func (a *AuthorizerOPA) Authorize(r *http.Request, session *authn.AuthenticationSession, config json.RawMessage, _ pipeline.Rule) error {
	c, err := a.Config(config)
	if err != nil {
		return err
	}

	templateID := c.PayloadTemplateID()

	upstreamReq := map[string]interface{}{}
	upstreamReq["method"] = r.Method

	if r.URL != nil {
		upstreamReq["path"] = r.URL.Path
		upstreamReq["query"] = r.URL.Query()
	}

	parsedBody, isBodyTruncated, err := getParsedBody(r)
	if err != nil {
		return errors.WithStack(err)
	}

	upstreamReq["body"] = parsedBody
	upstreamReq["is_body_truncated"] = isBodyTruncated

	input := &OpaInput{AuthenticationSession: session, UpstreamRequest: upstreamReq}
	jsonInput, err := json.Marshal(input)

	if err != nil {
		return errors.WithStack(err)
	}

	jsonInputReader := bytes.NewReader(jsonInput)

	if c.Payload != "" {
		a.vm.ExtCode("input", string(jsonInput))
		str, err := a.vm.EvaluateSnippet(templateID, c.Payload)

		if err != nil {
			return errors.WithStack(err)
		}

		jsonInputReader = bytes.NewReader([]byte(str))
	}

	req, err := http.NewRequest("POST", c.Endpoint, jsonInputReader)
	if err != nil {
		return errors.WithStack(err)
	}

	if req.Header.Get("Content-Type") == "" {
		req.Header.Add("Content-Type", "application/json")
	}

	res, err := a.client.Do(req)
	if err != nil {
		return errors.WithStack(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return errors.WithStack(err)
		}
		return errors.Errorf("expected status code %d but got %d %v", http.StatusOK, res.StatusCode, string(body))
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

func getParsedBody(req *http.Request) (interface{}, bool, error) {
	body := req.Body

	if body == nil {
		return nil, false, nil
	}

	var data interface{}

	if req.ContentLength >= 0 {
		if strings.Contains(req.Header.Get("content-type"), "application/json") {
			body, err := ioutil.ReadAll(body)
			if err != nil {
				return nil, false, err
			}

			err = json.Unmarshal(body, &data)
			if err != nil {
				return nil, false, err
			}
		}
	}

	return data, false, nil
}
