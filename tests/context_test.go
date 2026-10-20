package tests

import (
	"net/http/httptest"
	"testing"

	tools "github.com/ryuken/th_tools"
	"github.com/stretchr/testify/assert"
)

func TestContextValue(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)

	assert.Nil(t, tools.Value(r, "system"))

	r = tools.WithValue(r, "system", 3)

	assert.Equal(t, 3, tools.Value(r, "system"))
}
