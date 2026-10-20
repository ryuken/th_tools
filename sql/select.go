package sql

import (
	"fmt"
	"strings"
)

// Select builds a SELECT statement. Fragments passed to its methods are
// inserted into the SQL as-is, so never put user input in them: use ?
// placeholders and pass the values as params, then run the query with
// ToSQL() and Params().
type Select struct {
	Table       string
	Args        []string
	Joins       []string
	Filters     []string
	offset      uint
	limit       uint
	group       string
	order       string
	argParams   []interface{}
	joinParams  []interface{}
	whereParams []interface{}
}

func (s *Select) Reset() {
	s.Args = []string{}
	s.Joins = []string{}
	s.Filters = []string{}
	s.argParams = nil
	s.joinParams = nil
	s.whereParams = nil
}

func (s *Select) Set(arg string, params ...interface{}) {
	s.Args = append(s.Args, arg)
	s.argParams = append(s.argParams, params...)
}

func (s *Select) Where(arg string, params ...interface{}) {
	s.Filters = append(s.Filters, arg)
	s.whereParams = append(s.whereParams, params...)
}

func (s *Select) And(arg string, params ...interface{}) {
	s.Filters = append(s.Filters, "AND "+arg)
	s.whereParams = append(s.whereParams, params...)
}

func (s *Select) Or(arg string, params ...interface{}) {
	s.Filters = append(s.Filters, "OR "+arg)
	s.whereParams = append(s.whereParams, params...)
}

func (s *Select) Join(arg string, params ...interface{}) {
	s.Joins = append(s.Joins, arg)
	s.joinParams = append(s.joinParams, params...)
}

func (s *Select) GroupBy(g string) {
	s.group = g
}

func (s *Select) OrderBy(o string) {
	s.order = o
}

func (s *Select) Limit(i uint) {
	s.limit = i
}

func (s *Select) LimitRange(o uint, i uint) {
	s.offset = o
	s.limit = i
}

// Params returns the placeholder values in the order they appear in ToSQL()
func (s Select) Params() []interface{} {
	params := []interface{}{}
	params = append(params, s.argParams...)
	params = append(params, s.joinParams...)
	params = append(params, s.whereParams...)

	return params
}

func (s Select) ToSQL() string {

	build := fmt.Sprintf("SELECT %s FROM %s", strings.Join(s.Args, ", "), s.Table)

	if len(s.Joins) > 0 {
		build = fmt.Sprintf("%s %s", build, strings.Join(s.Joins, " "))
	}

	if len(s.Filters) > 0 {
		build = fmt.Sprintf("%s WHERE %s", build, strings.Join(s.Filters, " "))
	}

	if "" != s.group {
		build = fmt.Sprintf("%s GROUP BY %s", build, s.group)
	}

	if "" != s.order {
		build = fmt.Sprintf("%s ORDER BY %s", build, s.order)
	}

	if s.limit > 0 && s.offset > 0 {
		build = fmt.Sprintf("%s LIMIT %d, %d", build, s.offset, s.limit)
	} else if s.limit > 0 {
		build = fmt.Sprintf("%s LIMIT %d", build, s.limit)
	}

	return build
}
