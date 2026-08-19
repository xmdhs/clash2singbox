package convert

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddCidrBareAddresses(t *testing.T) {
	got, err := addCidr([]string{"10.0.0.2", "fd00::2"})
	assert.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.2/32", "fd00::2/128"}, got)
}

func TestAddCidrKeepsPrefix(t *testing.T) {
	got, err := addCidr([]string{"10.0.0.2/24", "fd00::2/64"})
	assert.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.2/24", "fd00::2/64"}, got)
}

func TestAddCidrSkipsEmpty(t *testing.T) {
	got, err := addCidr([]string{"", "1.1.1.1", ""})
	assert.NoError(t, err)
	assert.Equal(t, []string{"1.1.1.1/32"}, got)
}

func TestAddCidrInvalid(t *testing.T) {
	_, err := addCidr([]string{"not-an-ip"})
	assert.Error(t, err)
}
