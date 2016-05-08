package th_tools

import (
	"github.com/dchest/uniuri"
)

type Utils struct {
	String
}

type String struct{}

func (s String) Generate(length int) string {
	return uniuri.NewLen(length)
}

func (s String) GenerateChars(length int, chars []byte) string {
	return uniuri.NewLenChars(length, chars)
}
