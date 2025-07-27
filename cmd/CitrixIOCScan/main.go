package main

import (
	"encoding/json"
	"github.com/LeakIX/l9format"
	"github.com/leakix/HttpIOCScan"
	"log"
	"os"
	"sync"
)

var MaxRoutines = 1000

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("%s requires 2 arguments: <input_file.json> <config_file.json>", os.Args[0])
		os.Exit(1)
	}
	
	// Load detection rule
	rule, err := HttpIOCScan.LoadDetectionRule(os.Args[2])
	if err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}
	
	hostChannel := make(chan l9format.L9Event)
	waitGroup := &sync.WaitGroup{}
	StartHostScanners(waitGroup, MaxRoutines, hostChannel, rule)
	hostListJson, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	jsonDecoder := json.NewDecoder(hostListJson)
	for {
		var event l9format.L9Event
		err := jsonDecoder.Decode(&event)
		if err != nil {
			break
		}
		hostChannel <- event
	}
	close(hostChannel)
	waitGroup.Wait()
}

func StartHostScanners(waitGroup *sync.WaitGroup, num int, hostChan chan l9format.L9Event, rule *HttpIOCScan.DetectionRule) {
	OutputEncoder := json.NewEncoder(os.Stdout)
	HttpClient := HttpIOCScan.GetSaneHttpClient(MaxRoutines)
	for i := 0; i < num; i++ {
		hs := HttpIOCScan.HostScanner{
			WaitGroup:     waitGroup,
			HostChannel:   hostChan,
			OutputEncoder: OutputEncoder,
			HttpClient:    HttpClient,
			Rule:          rule,
		}
		go hs.Start()
	}
}

