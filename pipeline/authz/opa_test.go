package authz_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ory/viper"
	"github.com/ory/x/logrusx"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/pipeline/authn"
	. "github.com/ory/oathkeeper/pipeline/authz"
	"github.com/ory/oathkeeper/rule"
)

func TestAuthorizerOPAAuthorize(t *testing.T) {
	tests := []struct {
		name    string
		session *authn.AuthenticationSession
		config  json.RawMessage
		wantErr bool
	}{
		{
			name:    "invalid configuration",
			session: &authn.AuthenticationSession{},
			config:  json.RawMessage(`{}`),
			wantErr: true,
		},
		{
			name:    "unresolvable host",
			session: &authn.AuthenticationSession{},
			config:  json.RawMessage(`{"endpoint":"http://unresolvable-host/path","payload":"{}"}`),
			wantErr: true,
		},
		{
			name:    "invalid template",
			session: &authn.AuthenticationSession{},
			config:  json.RawMessage(`{"endpoint":"http://host/path","payload":"{{"}`),
			wantErr: true,
		},
		{
			name:    "unknown field",
			session: &authn.AuthenticationSession{},
			config:  json.RawMessage(`{"endpoint":"http://host/path","payload":"{{ .foo }}"}`),
			wantErr: true,
		},
		{
			name:    "invalid json",
			session: &authn.AuthenticationSession{},
			config:  json.RawMessage(`{"endpoint":"http://host/path","payload":"{"}`),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := configuration.NewViperProvider(logrusx.New("", ""))
			a := NewAuthorizerOPA(p)
			if err := a.Authorize(&http.Request{}, tt.session, tt.config, &rule.Rule{}); (err != nil) != tt.wantErr {
				t.Errorf("Authorize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthorizerOPAValidate(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		config  json.RawMessage
		wantErr bool
	}{
		{
			name:    "disabled",
			config:  json.RawMessage(`{}`),
			wantErr: true,
		},
		{
			name:    "empty configuration",
			enabled: true,
			config:  json.RawMessage(`{}`),
			wantErr: true,
		},
		{
			name:    "missing payload",
			enabled: true,
			config:  json.RawMessage(`{"endpoint":"http://host/path"}`),
			wantErr: true,
		},
		{
			name:    "missing endpoint",
			enabled: true,
			config:  json.RawMessage(`{"payload":"{}"}`),
			wantErr: true,
		},
		{
			name:    "invalid url",
			enabled: true,
			config:  json.RawMessage(`{"endpoint":"invalid-url","payload":"{}"}`),
			wantErr: true,
		},
		{
			name:    "valid configuration",
			enabled: true,
			config:  json.RawMessage(`{"endpoint":"http://host/path","headers":{"key":["value"]},"payload":"{}"}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := configuration.NewViperProvider(logrusx.New("", ""))
			a := NewAuthorizerOPA(p)
			viper.Set(configuration.ViperKeyAuthorizerOPAIsEnabled, tt.enabled)
			if err := a.Validate(tt.config); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
