package convert

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_portsToPort(t *testing.T) {
	_, err := portsToPort("443-43")
	assert.Error(t, err)

	port, _ := portsToPort("443-500")
	t.Log(port)
	if port < 443 || port > 500 {
		t.Fail()
	}

	for range 100 {
		port, _ := portsToPort("500-505")
		t.Log(port)
		if port < 500 || port > 505 {
			t.Fail()
		}
	}

	_, err = portsToPort("443-500/200-300,100-120")
	assert.Nil(t, err)

	_, err = portsToPort("100-100")
	assert.Nil(t, err)

}
