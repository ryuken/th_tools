package th_tools

import (
	"io/ioutil"
	"log"
)

type Config struct{}

func (c Config) Read() []byte {

	data, err := ioutil.ReadFile("config.json")

	if err != nil {
		log.Fatal(err)
	}

	return data
}
