package tests

import (
	"testing"

	"github.com/ryuken/th_tools/sql"
	"github.com/stretchr/testify/assert"
)

func TestSelectParams(t *testing.T) {
	s := sql.Select{Table: "accounts a"}
	s.Set("a.id")
	s.Join("INNER JOIN roles r ON r.account = a.id AND r.system = ?", 3)
	s.Where("a.email = ?", "x@example.com")
	s.And("a.is_active = ?", 1)
	s.LimitRange(20, 10)

	assert.Equal(t, "SELECT a.id FROM accounts a INNER JOIN roles r ON r.account = a.id AND r.system = ? WHERE a.email = ? AND a.is_active = ? LIMIT 20, 10", s.ToSQL())
	assert.Equal(t, []interface{}{3, "x@example.com", 1}, s.Params())
}

func TestUpdateParams(t *testing.T) {
	u := sql.Update{Table: "accounts"}
	u.Set("email = ?", "x@example.com")
	u.Where("id = ?", 7)
	u.Limit(1)

	assert.Equal(t, "UPDATE accounts SET email = ? WHERE id = ? LIMIT 1", u.ToSQL())
	assert.Equal(t, []interface{}{"x@example.com", 7}, u.Params())
}

func TestInsertParams(t *testing.T) {
	i := sql.Insert{Table: "accounts"}
	i.Set("null")
	i.Set("?", "x@example.com")

	assert.Equal(t, "INSERT INTO accounts VALUES(null, ?)", i.ToSQL())
	assert.Equal(t, []interface{}{"x@example.com"}, i.Params())
}
