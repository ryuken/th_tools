package sql

import (
	"fmt"
	"strings"
)

// Update builds an UPDATE statement. Fragments passed to its methods are
// inserted into the SQL as-is, so never put user input in them: use ?
// placeholders and pass the values as params, then run the query with
// ToSQL() and Params().
type Update struct {
	Table       string
	Args        []string
	Filters     []string
	limit       uint
	argParams   []interface{}
	whereParams []interface{}
}

func (u *Update) Reset() {
	u.Args = []string{}
	u.Filters = []string{}
	u.argParams = nil
	u.whereParams = nil
}

func (u *Update) Set(arg string, params ...interface{}) {
	u.Args = append(u.Args, arg)
	u.argParams = append(u.argParams, params...)
}

func (u *Update) Where(arg string, params ...interface{}) {
	u.Filters = append(u.Filters, arg)
	u.whereParams = append(u.whereParams, params...)
}

func (u *Update) And(arg string, params ...interface{}) {
	u.Filters = append(u.Filters, "AND "+arg)
	u.whereParams = append(u.whereParams, params...)
}

func (u *Update) Or(arg string, params ...interface{}) {
	u.Filters = append(u.Filters, "OR "+arg)
	u.whereParams = append(u.whereParams, params...)
}

func (u *Update) Limit(i uint) {
	u.limit = i
}

// Params returns the placeholder values in the order they appear in ToSQL()
func (u Update) Params() []interface{} {
	params := []interface{}{}
	params = append(params, u.argParams...)
	params = append(params, u.whereParams...)

	return params
}

func (u Update) ToSQL() string {

	build := fmt.Sprintf("UPDATE %s SET %s", u.Table, strings.Join(u.Args, ", "))

	if len(u.Filters) > 0 {
		build = fmt.Sprintf("%s WHERE %s", build, strings.Join(u.Filters, " "))
	}

	if u.limit > 0 {
		build = fmt.Sprintf("%s LIMIT %d", build, u.limit)
	}

	return build
}
