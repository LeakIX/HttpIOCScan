package CitrixIOCScan

import (
	"encoding/json"
	"fmt"
	"github.com/LeakIX/l9format"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"
)

type HostScanner struct {
	WaitGroup     *sync.WaitGroup
	HostChannel   chan l9format.L9Event
	HttpClient    *http.Client
	OutputEncoder *json.Encoder
	Urls          []string
}

func (hs *HostScanner) Start() {
	hs.WaitGroup.Add(1)
	defer hs.WaitGroup.Done()
	for host := range hs.HostChannel {
		host.Transports = []string{"tcp", "http", "tls"}
		log.Printf("Scanning host: %s", host.Url())
		hs.scanUrls(host)
		log.Printf("Finished scanning host: %s", host.Url())
	}
}

func (hs *HostScanner) testIfCitrixADC(event l9format.L9Event) bool {
	// Checking for a valid ctx page before scanning
	resp, err := hs.HttpClient.Get(event.Url() + "/logon/LogonPoint/init.js")
	if err != nil {
		log.Printf("Error scanning host %s: %v", event.Url(), err)
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		log.Printf("Error reading body for host %s: %v", event.Url(), err)
	}
	if !strings.Contains(string(body), "gatewaycustomStyle") {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	return true
}

func (hs *HostScanner) getNormalStatusCode(event l9format.L9Event) int {
	// Checking for a non-valid ctx page status code
	randNumber := rand.IntN(10000000)
	resp, err := hs.HttpClient.Get(event.Url() + fmt.Sprintf("/logon/LogonPoint/receiver/js/localization/file%d.php", randNumber))
	if err != nil {
		log.Printf("Error scanning host %s: %v", event.Url(), err)
		return 0
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func (hs *HostScanner) scan(event l9format.L9Event, uri string, expectedStatusCode int) (bool, error) {
	finalUrl := event.Url() + uri
	resp, err := hs.HttpClient.Get(finalUrl)
	if err != nil {
		log.Printf("Error scanning host/uri: %s", finalUrl, err)
		return false, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	log.Printf("Final results: [%d] %s", resp.StatusCode, finalUrl)
	if resp.StatusCode != expectedStatusCode {
		// This page is always 404
		if strings.HasSuffix(finalUrl, "/logon/logonPoint/index.php") && resp.StatusCode == 404 {
			return false, nil
		}
		if strings.HasPrefix(uri, "/logon/LogonPoint/receiver/css/themes_gw") && resp.StatusCode == 404 {
			return false, nil
		}
		if len(resp.TLS.PeerCertificates) > 0 {
			event.SSL.Certificate.CommonName = resp.TLS.PeerCertificates[0].Subject.CommonName
			event.SSL.Certificate.Domains = resp.TLS.PeerCertificates[0].DNSNames
		}
		event.EventType = "leak"
		event.EventSource = "CitrixIOScan"
		event.EventPipeline = append(event.EventPipeline, event.EventSource)
		event.Summary = "Citrix ADC abnormal reply:\n"
		event.Summary += fmt.Sprintf("Found %d instead of %d on %s", resp.StatusCode, expectedStatusCode, finalUrl)
		event.Leak.Severity = "critical"
		event.Leak.Dataset.Infected = true
		err = hs.OutputEncoder.Encode(event)
		if err != nil {
			panic(err)
		}
		return true, nil
	}
	return false, nil
}

func (hs *HostScanner) scanUrls(event l9format.L9Event) {
	// Check if really ADC
	if !hs.testIfCitrixADC(event) {
		return
	}
	// Get a usual status code for non-existing PHP pages
	normalStatusCode := hs.getNormalStatusCode(event)
	if normalStatusCode == 0 {
		return
	}
	// Go over URLs and check for 200s
	connErrorCount := 0
	for _, uri := range hs.Urls {
		found, err := hs.scan(event, uri, normalStatusCode)
		// If found, no need to go deeper
		if found {
			break
		}
		// If more than 5 connection error, stop
		if err != nil {
			connErrorCount++
			if connErrorCount > 5 {
				break
			}
		}
		// Wait a relatively safe random time before checking the next URL
		dur := 1 * time.Second
		dur += time.Duration(rand.IntN(900)) * time.Millisecond
		time.Sleep(dur)
	}
}
