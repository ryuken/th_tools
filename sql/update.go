package sql

import (
	"fmt"
	"strings"
)

type Update struct {
	Table   string
	Args    []string
	Filters []string
	limit   uint
}

func (u *Update) Reset() {
	u.Args = []string{}
	u.Filters = []string{}
}

func (u *Update) Set(arg string) {
	u.Args = append(u.Args, arg)
}

func (u *Update) Where(arg string) {
	u.Filters = append(u.Filters, arg)
}

func (u *Update) And(arg string) {
	u.Filters = append(u.Filters, "AND "+arg)
}

func (u *Update) Or(arg string) {
	u.Filters = append(u.Filters, "OR "+arg)
}

func (u *Update) Limit(i uint) {
	u.limit = i
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
