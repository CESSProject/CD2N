package main

import (
	"log"

	"github.com/CD2N/CD2N/cacher/run/cmd"
)

const VERSION = "v0.1.0"

func main() {
	log.Println("CODE VERSION:", VERSION)
	cmd.InitCmd()
	cmd.Execute()
}
