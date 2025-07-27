package HttpIOCScan

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
	Rule          *DetectionRule
	Delay         time.Duration
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

func (hs *HostScanner) testSoftwareFingerprint(event l9format.L9Event, rule DetectionRule) bool {
	// Test if target matches the software fingerprint
	resp, err := hs.HttpClient.Get(event.Url() + rule.FingerprintCheck.Uri)
	if err != nil {
		log.Printf("Error fingerprinting host %s with rule %s: %v", event.Url(), rule.Name, err)
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		log.Printf("Error reading fingerprint body for host %s: %v", event.Url(), err)
		return false
	}
	if !strings.Contains(string(body), rule.FingerprintCheck.ExpectedContent) {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	log.Printf("Host %s matches %s fingerprint", event.Url(), rule.Name)
	return true
}

func (hs *HostScanner) getNormalStatusCodeForRule(event l9format.L9Event, rule DetectionRule) int {
	// Get expected status code for non-existent files using rule's test Uri
	randNumber := rand.IntN(10000000)
	resp, err := hs.HttpClient.Get(event.Url() + fmt.Sprintf(rule.NonExistentFileUri, randNumber))
	if err != nil {
		log.Printf("Error getting baseline status code for host %s with rule %s: %v", event.Url(), rule.Name, err)
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	log.Printf("Baseline status code for %s (%s): %d", event.Url(), rule.Name, resp.StatusCode)
	return resp.StatusCode
}

func (hs *HostScanner) scanWithRule(event l9format.L9Event, uri string, expectedStatusCode int, rule DetectionRule) (bool, error) {
	finalUrl := event.Url() + uri
	resp, err := hs.HttpClient.Get(finalUrl)
	if err != nil {
		log.Printf("Error scanning host/uri: %s: %v", finalUrl, err)
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	log.Printf("Scan results: [%d] %s", resp.StatusCode, finalUrl)
	if resp.StatusCode != expectedStatusCode {
		// Check rule-specific exclusions
		for _, exception := range rule.ExceptionURLs {
			if strings.Contains(uri, exception.Uri) && resp.StatusCode == exception.StatusCode {
				return false, nil
			}
		}
		if len(resp.TLS.PeerCertificates) > 0 {
			event.SSL.Certificate.CommonName = resp.TLS.PeerCertificates[0].Subject.CommonName
			event.SSL.Certificate.Domains = resp.TLS.PeerCertificates[0].DNSNames
		}
		event.EventType = "leak"
		event.EventSource = "GenericIOCScan"
		event.EventPipeline = append(event.EventPipeline, event.EventSource)
		event.Summary = fmt.Sprintf("%s abnormal reply:\n", rule.Name)
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
	// Check if target matches this rule's fingerprint
	if !hs.testSoftwareFingerprint(event, *hs.Rule) {
		return
	}
	// Get normal status code for non-existing files
	normalStatusCode := hs.getNormalStatusCodeForRule(event, *hs.Rule)
	if normalStatusCode == 0 {
		return
	}
	// Scan IOCs for this rule
	connErrorCount := 0
	for _, uri := range hs.Rule.IOCs {
		found, err := hs.scanWithRule(event, uri, normalStatusCode, *hs.Rule)
		// If found, no need to go deeper
		if found {
			return
		}
		// If more than 5 connection error, stop
		if err != nil {
			connErrorCount++
			if connErrorCount > 5 {
				break
			}
		}
		// Wait a relatively safe random time before checking the next Uri
		dur := hs.Delay
		if dur == 0 {
			dur = 1 * time.Second
		}
		dur += time.Duration(rand.IntN(900)) * time.Millisecond
		time.Sleep(dur)
	}
}
