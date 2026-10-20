package tests

import (
	"testing"

	tools "github.com/ryuken/th_tools"
	"github.com/stretchr/testify/assert"
)

func TestCheckPassword(t *testing.T) {
	hash, err := tools.HashPassword("hunter2")
	assert.Nil(t, err)

	ok, rehash := tools.CheckPassword(hash, "hunter2")
	assert.True(t, ok)
	assert.False(t, rehash)

	ok, _ = tools.CheckPassword(hash, "wrong")
	assert.False(t, ok)

	// unsalted SHA-512 of "hunter2", as stored before bcrypt
	legacy := "6b97ed68d14eb3f1aa959ce5d49c7dc612e1eb1dafd73b1e705847483fd6a6c809f2ceb4e8df6ff9984c6298ff0285cace6614bf8daa9f0070101b6c89899e22"

	ok, rehash = tools.CheckPassword(legacy, "hunter2")
	assert.True(t, ok)
	assert.True(t, rehash)

	ok, rehash = tools.CheckPassword(legacy, "wrong")
	assert.False(t, ok)
	assert.False(t, rehash)
}
