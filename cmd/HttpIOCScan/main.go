package main

import (
	"encoding/json"
	"github.com/LeakIX/l9format"
	"github.com/alecthomas/kong"
	"github.com/leakix/HttpIOCScan"
	"log"
	"os"
	"sync"
	"time"
)

type CLI struct {
	InputFile  string        `arg:"" name:"input" help:"JSON file containing targets to scan" type:"existingfile"`
	ConfigFile string        `arg:"" name:"config" help:"JSON configuration file with detection rules" type:"existingfile"`
	Routines   int           `short:"r" long:"routines" help:"Number of concurrent scanning routines" default:"1000"`
	Delay      time.Duration `short:"d" long:"delay" help:"Base delay between requests (randomized +0-900ms)" default:"1s"`
}

func main() {
	cli := CLI{}
	ctx := kong.Parse(&cli)

	// Load detection rule
	rule, err := HttpIOCScan.LoadDetectionRule(cli.ConfigFile)
	if err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

	hostChannel := make(chan l9format.L9Event)
	waitGroup := &sync.WaitGroup{}
	StartHostScanners(waitGroup, cli.Routines, hostChannel, rule, cli.Delay)
	hostListJson, err := os.Open(cli.InputFile)
	if err != nil {
		ctx.Fatalf("Error opening input file: %v", err)
	}
	defer hostListJson.Close()

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

func StartHostScanners(waitGroup *sync.WaitGroup, maxRoutines int, hostChan chan l9format.L9Event, rule *HttpIOCScan.DetectionRule, delay time.Duration) {
	OutputEncoder := json.NewEncoder(os.Stdout)
	HttpClient := HttpIOCScan.GetSaneHttpClient(maxRoutines)
	for i := 0; i < maxRoutines; i++ {
		hs := HttpIOCScan.HostScanner{
			WaitGroup:     waitGroup,
			HostChannel:   hostChan,
			OutputEncoder: OutputEncoder,
			HttpClient:    HttpClient,
			Rule:          rule,
			Delay:         delay,
		}
		go hs.Start()
	}
}
