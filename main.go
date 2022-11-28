package main

import (
	"encoding/json"
	"fmt"
	"github.com/richardjennings/tapo/pkg/tapo"
	"log"
	"os"
)

func main() {
	var t *tapo.Tapo
	var r map[string]interface{}
	var err error

	if len(os.Args) != 5 {
		log.Fatalln("expected ip username password command")
	}

	ip := os.Args[1]
	username := os.Args[2]
	password := os.Args[3]
	command := os.Args[4]

	t, err = tapo.NewTapo(ip, username, password)
	HandleError(err)

	switch command {
	case "off":
		r, err = t.TurnOff()
	case "on":
		r, err = t.TurnOn()
	case "energy-usage":
		r, err = t.GetEnergyUsage()
	case "device-info":
		r, err = t.DeviceInfo()
	default:
		log.Fatalf("invalid argument: '%s'. expected one of [off, on, energy-usage, device-info]", command)
	}
	HandleError(err)
	b, err := json.MarshalIndent(r, "", "  ")
	HandleError(err)
	_, _ = fmt.Fprintln(os.Stdout, string(b))
}

func HandleError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
