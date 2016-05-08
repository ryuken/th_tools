package sql

import (
	"fmt"
	"strings"
)

type Select struct {
	Table   string
	Args    []string
	Joins   []string
	Filters []string
	offset  uint
	limit   uint
	group   string
	order   string
}

func (s *Select) Reset() {
	s.Args = []string{}
	s.Joins = []string{}
	s.Filters = []string{}
}

func (s *Select) Set(arg string) {
	s.Args = append(s.Args, arg)
}

func (s *Select) Where(arg string) {
	s.Filters = append(s.Filters, arg)
}

func (s *Select) And(arg string) {
	s.Filters = append(s.Filters, "AND "+arg)
}

func (s *Select) Or(arg string) {
	s.Filters = append(s.Filters, "OR "+arg)
}

func (s *Select) Join(arg string) {
	s.Joins = append(s.Joins, arg)
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

	if s.limit > 0 {
		build = fmt.Sprintf("%s LIMIT %d", build, s.limit)
	}

	return build
}
