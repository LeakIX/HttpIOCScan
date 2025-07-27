package main

import (
	"bufio"
	"encoding/json"
	"github.com/LeakIX/l9format"
	"github.com/alecthomas/kong"
	"github.com/leakix/HttpIOCScan"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type CLI struct {
	InputFile  string        `arg:"" name:"input" help:"JSON file containing targets to scan OR text file with URLs (one per line)" type:"existingfile"`
	ConfigFile string        `arg:"" name:"config" help:"JSON configuration file with detection rules" type:"existingfile"`
	Routines   int           `short:"r" long:"routines" help:"Number of concurrent scanning routines" default:"1000"`
	Delay      time.Duration `short:"d" long:"delay" help:"Base delay between requests (randomized +0-900ms)" default:"1s"`
}

// parseURL converts a URL string to an L9Event
func parseURL(urlStr string) (l9format.L9Event, error) {
	parsedURL, err := url.Parse(strings.TrimSpace(urlStr))
	if err != nil {
		return l9format.L9Event{}, err
	}

	// Default to HTTPS port if no port specified
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}

	host := parsedURL.Hostname()
	
	return l9format.L9Event{
		Ip:   host, // Will be resolved during scanning
		Port: port,
		Host: host,
	}, nil
}

// isJSONFormat checks if the first line of the file looks like JSON
func isJSONFormat(filename string) (bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		return strings.HasPrefix(line, "{") && strings.Contains(line, "\""), nil
	}
	return false, scanner.Err()
}

func main() {
	cli := CLI{}
	ctx := kong.Parse(&cli)

	// Load detection rule
	rule, err := HttpIOCScan.LoadDetectionRule(cli.ConfigFile)
	if err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

	// Prepare host scanners
	hostChannel := make(chan l9format.L9Event)
	waitGroup := &sync.WaitGroup{}
	OutputEncoder := json.NewEncoder(os.Stdout)
	HttpClient := HttpIOCScan.GetSaneHttpClient(cli.Routines)
	// Start host scanners
	for i := 0; i < cli.Routines; i++ {
		hs := HttpIOCScan.HostScanner{
			WaitGroup:     waitGroup,
			HostChannel:   hostChannel,
			OutputEncoder: OutputEncoder,
			HttpClient:    HttpClient,
			Rule:          rule,
			Delay:         cli.Delay,
		}
		go hs.Start()
	}
	// Determine input format and load targets
	isJSON, err := isJSONFormat(cli.InputFile)
	if err != nil {
		ctx.Fatalf("Error checking input file format: %v", err)
	}

	inputFile, err := os.Open(cli.InputFile)
	if err != nil {
		ctx.Fatalf("Error opening input file: %v", err)
	}
	defer inputFile.Close()

	if isJSON {
		// Handle JSON format (existing behavior)
		jsonDecoder := json.NewDecoder(inputFile)
		for {
			var event l9format.L9Event
			err := jsonDecoder.Decode(&event)
			if err != nil {
				break
			}
			hostChannel <- event
		}
	} else {
		// Handle URL list format (new behavior)
		scanner := bufio.NewScanner(inputFile)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
				continue // Skip lines not starting with http:// or https://
			}
			
			event, err := parseURL(line)
			if err != nil {
				log.Printf("Error parsing URL '%s': %v", line, err)
				continue
			}
			hostChannel <- event
		}
		
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading input file: %v", err)
		}
	}
	close(hostChannel)
	waitGroup.Wait()
}
