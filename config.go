package th_tools

import (
    "os"
    "log"

    "github.com/antonholmquist/jason"
)

type Config struct {}

func (c Config) Read() *jason.Object {

    file, err := os.Open("config.json")

    if err != nil {
        log.Fatal(err)
    }

    values, err := jason.NewObjectFromReader(file)

    if err != nil {
        log.Println(err)
    }

    return values
}
