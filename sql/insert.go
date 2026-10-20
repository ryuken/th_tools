package sql

import (
	"fmt"
	"strings"
)

// Insert builds an INSERT statement. Values passed to Set are inserted into
// the SQL as-is, so never put user input in them: use Set("?", value) and
// run the query with ToSQL() and Params().
type Insert struct {
	Table  string
	Args   []string
	params []interface{}
}

func (i *Insert) Reset() {
	i.Args = []string{}
	i.params = nil
}

func (i *Insert) Set(arg string, params ...interface{}) {
	i.Args = append(i.Args, arg)
	i.params = append(i.params, params...)
}

// Params returns the placeholder values in the order they appear in ToSQL()
func (i Insert) Params() []interface{} {
	return append([]interface{}{}, i.params...)
}

func (i Insert) ToSQL() string {
	return fmt.Sprintf("INSERT INTO %s VALUES(%s)", i.Table, strings.Join(i.Args, ", "))
}
