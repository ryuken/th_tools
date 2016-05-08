package sql

import (
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type FlexFetch struct{}

func (f FlexFetch) Select(db *sqlx.DB, sql string, params []interface{}) ([]interface{}, error) {

	var result []interface{}

	rows, err := db.Query(sql, params...)

	if err != nil {
		return nil, err
	}

	columns, _ := rows.Columns()
	count := len(columns)
	values := make([]interface{}, count)
	valuePtrs := make([]interface{}, count)

	for rows.Next() {

		entity := make(map[string]interface{})

		for i := range columns {
			valuePtrs[i] = &values[i]
		}

		rows.Scan(valuePtrs...)

		for i, col := range columns {

			var v interface{}

			val := values[i]

			b, ok := val.([]byte)

			if ok {
				v = string(b)
			} else {
				v = val
			}

			entity[col] = v
		}

		result = append(result, entity)
	}

	return result, nil
}

func (f FlexFetch) Get(db *sqlx.DB, sql string, params []interface{}) (map[string]interface{}, error) {

	entity := make(map[string]interface{})

	rows, err := db.Query(sql, params...)

	if err != nil {
		return nil, err
	}

	columns, _ := rows.Columns()
	count := len(columns)
	values := make([]interface{}, count)
	valuePtrs := make([]interface{}, count)

	for rows.Next() {

		for i := range columns {
			valuePtrs[i] = &values[i]
		}

		rows.Scan(valuePtrs...)

		for i, col := range columns {

			var v interface{}

			val := values[i]

			b, ok := val.([]byte)

			if ok {
				v = string(b)
			} else {
				v = val
			}

			entity[col] = v
		}
	}

	return entity, nil
}
