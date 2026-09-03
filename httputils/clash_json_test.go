package httputils

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSingValidJSONScalar(t *testing.T) {
	outbounds, tags, proxies, err := getSing([]byte(`true`), "example.com", false)
	require.NoError(t, err)
	assert.Empty(t, outbounds)
	assert.Empty(t, tags)
	assert.Empty(t, proxies)
}

func TestGetSingValidJSONWithoutOutbounds(t *testing.T) {
	outbounds, tags, proxies, err := getSing([]byte(`{"log":{}}`), "example.com", false)
	require.NoError(t, err)
	assert.Empty(t, outbounds)
	assert.Empty(t, tags)
	assert.Empty(t, proxies)
}

func TestGetSingValidJSONClashDocument(t *testing.T) {
	outbounds, tags, proxies, err := getSing([]byte(`{"proxies":[{"name":"n1"}]}`), "example.com", false)
	require.NoError(t, err)
	assert.Empty(t, outbounds)
	assert.Empty(t, tags)
	assert.Empty(t, proxies)
}

func TestGetAnyJSONClashDocumentUsesYAML(t *testing.T) {
	client := &http.Client{Transport: staticRT{status: http.StatusOK, body: []byte(`{"proxies":[{"name":"n1","type":"vmess","server":"example.com","port":"443","uuid":"u"}]}`)}}

	c, singList, tags, err := GetAny(context.Background(), client, "https://example.com/sub", false)
	require.NoError(t, err)
	require.Len(t, c.Proxies, 1)
	assert.Equal(t, "n1", c.Proxies[0].Name)
	assert.Empty(t, singList)
	assert.Empty(t, tags)
}

func TestGetSingObjectOutbound(t *testing.T) {
	outbounds, tags, proxies, err := getSing([]byte(`{"outbounds":{"type":"vmess","tag":"n1"}}`), "example.com", false)
	require.NoError(t, err)
	require.Len(t, outbounds, 1)
	assert.Equal(t, "n1", outbounds[0]["tag"])
	assert.Equal(t, []string{"n1"}, tags)
	assert.Empty(t, proxies)
}

func TestGetSingJSONAddTag(t *testing.T) {
	outbounds, tags, proxies, err := getSing([]byte(`{"outbounds":[{"type":"vmess","tag":"n1"},{"type":"shadowtls","tag":"stls"}]}`), "example.com", true)
	require.NoError(t, err)
	require.Len(t, outbounds, 2)
	assert.Equal(t, "n1[example.com]", outbounds[0]["tag"])
	assert.Equal(t, "stls[example.com]", outbounds[1]["tag"])
	assert.Equal(t, []string{"n1[example.com]"}, tags)
	assert.Empty(t, proxies)
}
