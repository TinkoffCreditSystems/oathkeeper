package auditlog

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gobuffalo/packr/v2"
	"github.com/ory/gojsonschema"
	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/oathkeeper/proxy"
	"github.com/tidwall/gjson"
)

var schemas = packr.New("schemas", "../.schema")

const auditLogConfigSchemaPath = "auditlog.schema.json"

// EventBuilder is a type to build the Event structure.
type EventBuilder struct {
	URLPattern          string `json:"url_pattern"`
	Method              string `json:"http_method"`
	ResponseCodes       []int  `json:"http_response_codes"`
	Filter              Filter `json:"filter"`
	Class               string `json:"class"`
	DescriptionTemplate string `json:"description_template"`

	r *regexp.Regexp
}

type Filter struct {
	RequestHeaderWhiteList  []string `json:"request_header"`
	RequestBodyWhiteList    []string `json:"request_body"`
	ResponseHeaderWhiteList []string `json:"response_header"`
	ResponseBodyWhiteList   []string `json:"response_body"`
	TakeWholeResponseBody   bool     `json:"full_response_body"`
}

// UnmarshalJSON implements the Unmarshaler interface for the EventBuilder struct.
func (b *EventBuilder) UnmarshalJSON(raw []byte) error {
	var err error

	// EventBuilderAlias to prevent an infinite loop while unmarshalling.
	type EventBuilderAlias EventBuilder

	bb := &struct {
		*EventBuilderAlias
	}{
		EventBuilderAlias: (*EventBuilderAlias)(b),
	}

	if err = json.Unmarshal(raw, &bb); err != nil {
		return err
	}

	b.r, err = regexp.Compile(b.URLPattern)

	return err
}

// Match method verifies if this builder must be applied to request with given url and method.
func (b *EventBuilder) Match(url, method string, statusCode int) bool {
	responseCodeMatches := len(b.ResponseCodes) == 0 || intInSlice(statusCode, b.ResponseCodes)

	return responseCodeMatches && strings.EqualFold(b.Method, method) && b.r.MatchString(url)
}

func intInSlice(a int, list []int) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}

	return false
}

// Build method performs filtering of data using rules from config.
func (b *EventBuilder) Build(req *RequestWithBytesBody, resp *ResponseWithBytesBody, err error) (*Event, error) {
	e := NewEvent()

	if req != nil {
		e.Details.Meta["method"] = req.Method
		e.Details.Meta["url"] = req.URL.String()
		e.Details.Meta["user_ip"] = req.RemoteAddr

		if sess, ok := req.Context().Value(proxy.ContextKeySession).(*authn.AuthenticationSession); ok {
			e.Details.Meta["user_id"] = sess.Subject
		}

		e.Details.RequestHeader = filterHeader(req.Header, b.Filter.RequestHeaderWhiteList)
		e.Details.RequestBody = filterBody(req.Body, b.Filter.RequestBodyWhiteList)
	}

	if err != nil {
		e.Details.OathkeeperError = err
	}

	if resp != nil {
		e.Details.Meta["status_code"] = strconv.Itoa(resp.StatusCode)

		e.Details.ResponseHeader = filterHeader(resp.Header, b.Filter.ResponseHeaderWhiteList)
		e.Details.ResponseBody = filterBody(resp.Body, b.Filter.ResponseBodyWhiteList)

		if b.Filter.TakeWholeResponseBody {
			_ = json.Unmarshal(resp.Body, &e.Details.FullResponseBody)
		}
	}

	// TODO(torilov) generate Description.
	e.Description = ""
	e.Class = b.Class

	return &e, nil
}

func filterBody(body []byte, wl []string) map[string]interface{} {
	result := make(map[string]interface{})

	if !gjson.ValidBytes(body) {
		return result
	}

	for _, key := range wl {
		r := gjson.GetBytes(body, key)
		if r.Exists() {
			result[key] = r.Value()
		}
	}

	return result
}

func filterHeader(h http.Header, wl []string) map[string][]string {
	result := make(map[string][]string)

	for _, key := range wl {
		vs := h.Values(key)
		if len(vs) != 0 {
			result[key] = vs
		}
	}

	return result
}

// DeserializeEventBuildersFromFiles validates and deserializes an array of event builders.
func DeserializeEventBuildersFromFiles(configPath string) ([]EventBuilder, error) {
	config, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	schema, err := schemas.Find(auditLogConfigSchemaPath)
	if err != nil {
		return nil, err
	}

	return DeserializeEventBuildersFromBytes(config, schema)
}

// DeserializeEventBuildersFromBytes validates and deserializes an array of event builders.
func DeserializeEventBuildersFromBytes(config, schema []byte) ([]EventBuilder, error) {
	if err := validateJSONConfigSchema(config, schema); err != nil {
		return nil, err
	}

	return deserializeJSONConfig(config)
}

func validateJSONConfigSchema(config, schema []byte) error {
	configLoader := gojsonschema.NewBytesLoader(config)
	schemaLoader := gojsonschema.NewBytesLoader(schema)

	if result, err := gojsonschema.Validate(schemaLoader, configLoader); err != nil {
		return err
	} else if !result.Valid() {
		descriptions := make([]string, 0)
		for _, d := range result.Errors() {
			descriptions = append(descriptions, d.String())
		}

		return errors.New(strings.Join(descriptions, ";"))
	}

	return nil
}

func deserializeJSONConfig(config []byte) ([]EventBuilder, error) {
	var builders []EventBuilder

	if err := json.Unmarshal(config, &builders); err != nil {
		return nil, err
	}

	return builders, nil
}
