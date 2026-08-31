package singbox

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSingObfsPlainString(t *testing.T) {
	b, err := json.Marshal(SingObfs{Value: "pass"})
	require.NoError(t, err)
	assert.Equal(t, `"pass"`, string(b))
}

func TestSingObfsHysteria2Object(t *testing.T) {
	b, err := json.Marshal(SingObfs{Value: "obfs-pass", Type: "salamander"})
	require.NoError(t, err)
	assert.Equal(t, `{"password":"obfs-pass","type":"salamander"}`, string(b))
}

func TestSingRealmMarshalWithToken(t *testing.T) {
	out := SingBoxOut{
		Type: "hysteria2",
		Tag:  "hy2",
		Realm: &SingRealm{
			ServerUrl:   "https://realm.hy2.io",
			Token:       "public",
			RealmId:     "my-id",
			StunServers: []string{"stun.example.com:3478"},
		},
	}
	b, err := json.Marshal(out)
	require.NoError(t, err)
	s := string(b)
	assert.Contains(t, s, `"server_url":"https://realm.hy2.io"`)
	assert.Contains(t, s, `"token":"public"`)
	assert.Contains(t, s, `"realm_id":"my-id"`)
	assert.Contains(t, s, `"stun_servers":["stun.example.com:3478"]`)
	assert.NotContains(t, s, `"server":`)
	assert.NotContains(t, s, `"server_port":`)
}

func TestSingRealmMarshalWithoutToken(t *testing.T) {
	out := SingBoxOut{
		Type: "hysteria2",
		Tag:  "hy2",
		Realm: &SingRealm{
			ServerUrl:   "https://realm.hy2.io",
			RealmId:     "my-id",
			StunServers: []string{"stun.example.com:3478"},
		},
	}
	b, err := json.Marshal(out)
	require.NoError(t, err)
	assert.NotContains(t, string(b), `"token"`)
}

func TestSingRealmOmittedWhenNil(t *testing.T) {
	out := SingBoxOut{Type: "hysteria2", Tag: "hy2"}
	b, err := json.Marshal(out)
	require.NoError(t, err)
	assert.NotContains(t, string(b), `"realm"`)
}
