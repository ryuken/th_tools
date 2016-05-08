package sql

import (
	"fmt"
	"strings"
)

type Insert struct {
	Table string
	Args []string
}

func (i *Insert) Reset() {
	i.Args = []string{}
}

func (i *Insert) Set(arg string) {
	i.Args = append(i.Args, arg)
}

func (i Insert) ToSQL() string {
	return fmt.Sprintf("INSERT INTO %s VALUES(%s)", i.Table, strings.Join(i.Args, ", "))
}
