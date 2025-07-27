package HttpIOCScan

import (
	"crypto/tls"
	"net/http"
	"time"
)

func GetSaneHttpClient(maxRoutines int) *http.Client {
	return &http.Client{
		Timeout: time.Second * 5,
		Transport: &http.Transport{
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: 1024 * 64,
			MaxIdleConnsPerHost:    1,
			MaxConnsPerHost:        1,
			TLSClientConfig: &tls.Config{
				ClientSessionCache: tls.NewLRUClientSessionCache(maxRoutines),
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
