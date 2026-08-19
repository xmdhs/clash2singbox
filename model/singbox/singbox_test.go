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
