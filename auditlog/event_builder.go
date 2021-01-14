package auditlog

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gobuffalo/packr/v2"
	"github.com/ory/gojsonschema"
	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/oathkeeper/proxy"
)

var schemas = packr.New("schemas", "../../.schema")

const auditLogConfigSchemaPath = "auditlog.schema.json"

// EventBuilder is a type to build the Event structure.
type EventBuilder struct {
	URLPattern          string `json:"url_pattern"`
	Method              string `json:"http_method"`
	Filter              Filter `json:"filter"`
	DescriptionTemplate string `json:"description_template"`

	r *regexp.Regexp
}

type Filter struct {
	RequestHeaderWhiteList  []string `json:"request_header"`
	RequestBodyWhiteList    []string `json:"request_body"`
	ResponseHeaderWhiteList []string `json:"response_header"`
	ResponseBodyWhiteList   []string `json:"response_body"`
}

// UnmarshalJSON implements the Unmarshaler interface for the EventBuilder struct.
func (b *EventBuilder) UnmarshalJSON(raw []byte) error {
	var err error

	// An additional struct like in rule.go.
	var bb struct {
		URLPattern          string `json:"url_pattern"`
		Method              string `json:"http_method"`
		Filter              Filter `json:"filter"`
		DescriptionTemplate string `json:"description_template"`
		r                   *regexp.Regexp
	}

	if err = json.Unmarshal(raw, &bb); err != nil {
		return err
	}

	*b = bb
	b.r, err = regexp.Compile(b.URLPattern)

	return err
}

// Match method verifies if this builder must be applied to request with given url and method.
func (b *EventBuilder) Match(url, method string) bool {
	return strings.EqualFold(b.Method, method) && b.r.MatchString(url)
}

// Build method performs filtering of data using rules from config.
func (b *EventBuilder) Build(req *http.Request, resp *http.Response, err error) (*Event, error) {
	e := NewEvent()

	if req != nil {
		e.Meta["method"] = req.Method
		e.Meta["url"] = req.URL.String()
		e.Meta["user_ip"] = req.RemoteAddr

		if sess, ok := req.Context().Value(proxy.ContextKeySession).(*authn.AuthenticationSession); ok {
			e.Meta["user_id"] = sess.Subject
		}

		e.RequestHeader = filterHeader(req.Header, b.Filter.RequestHeaderWhiteList)
		e.RequestBody = filterBody(req.Body, b.Filter.RequestBodyWhiteList)
	}

	if err != nil {
		e.OathkeeperError = err
	}

	if resp != nil {
		e.Meta["status_code"] = strconv.Itoa(resp.StatusCode)

		e.ResponseHeader = filterHeader(resp.Header, b.Filter.ResponseHeaderWhiteList)
		e.ResponseBody = filterBody(resp.Body, b.Filter.ResponseBodyWhiteList)
	}

	// TODO(torilov) generate Description.
	e.Description = ""

	return &e, nil
}

func filterBody(b io.Reader, wl []string) map[string]interface{} {
	result := make(map[string]interface{})

	if b == nil {
		return result
	}

	bb, err := ioutil.ReadAll(b)
	if err != nil {
		return result
	}

	var body map[string]interface{}
	if err = json.Unmarshal(bb, &body); err != nil {
		return result
	}

NextWhitelistItem:
	for _, key := range wl {
		var value interface{} = body
		for _, k := range strings.Split(key, ".") {
			var ok bool

			m, ok := value.(map[string]interface{})
			if !ok {
				continue NextWhitelistItem
			}

			value, ok = m[k]
			if !ok {
				continue NextWhitelistItem
			}
		}
		result[key] = value
	}

	return result
}

func filterHeader(h http.Header, wl []string) map[string]string {
	result := make(map[string]string)
	for _, key := range wl {
		result[key] = h.Get(key)
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
