package main

import (
	"bufio"
	"encoding/json"
	"github.com/LeakIX/l9format"
	"github.com/leakix/CitrixIOCScan"
	"log"
	"os"
	"strings"
	"sync"
)

var MaxRoutines = 1000

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("%s requires at least 2 arguments: <url_list.txt> and <input_file.json>", os.Args[0])
		os.Exit(1)
	}
	loadUrlList()
	hostChannel := make(chan l9format.L9Event)
	waitGroup := &sync.WaitGroup{}
	StartHostScanners(waitGroup, MaxRoutines, hostChannel)
	hostListJson, err := os.Open(os.Args[2])
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

func StartHostScanners(waitGroup *sync.WaitGroup, num int, hostChan chan l9format.L9Event) {
	OutputEncoder := json.NewEncoder(os.Stdout)
	HttpClient := CitrixIOCScan.GetSaneHttpClient(MaxRoutines)
	UrlList := loadUrlList()
	for i := 0; i < num; i++ {
		hs := CitrixIOCScan.HostScanner{
			WaitGroup:     waitGroup,
			HostChannel:   hostChan,
			OutputEncoder: OutputEncoder,
			HttpClient:    HttpClient,
			Urls:          UrlList,
		}
		go hs.Start()
	}
}

func loadUrlList() []string {
	var urls []string
	file, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), "/") {
			continue
		}
		urls = append(urls, scanner.Text())
	}
	if len(urls) == 0 {
		log.Fatal("No urls found")
	}
	return urls
}
