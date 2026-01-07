package main

import (
	"log"

	"github.com/CESSProject/CD2N/cacher/run/cmd"
)

const VERSION = "v0.1.1"

func main() {
	log.Println("CODE VERSION:", VERSION)
	cmd.InitCmd()
	cmd.Execute()
}
