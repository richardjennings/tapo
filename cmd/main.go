package main

import (
	"fmt"
	"log"
	"os"
	"tapo"
)

func main() {
	var t *tapo.Tapo
	var err error

	if len(os.Args) != 4 {
		log.Fatalln("expected ip username password")
	}

	ip := os.Args[1]
	username := os.Args[2]
	password := os.Args[3]

	t, err = tapo.NewTapo(ip, username, password)
	if err != nil {
		log.Fatalln(err)
	}

	r, err := t.GetEnergyUsage()
	if err != nil {
		log.Fatalln(err)
	}

	for k, v := range r["result"].(map[string]interface{}) {
		fmt.Println(k, v)
	}
}
