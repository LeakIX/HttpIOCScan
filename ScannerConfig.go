package HttpIOCScan

import (
	"encoding/json"
	"os"
)

type DetectionRule struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	FingerprintCheck struct {
		Uri             string `json:"uri"`
		ExpectedContent string `json:"expected_content"`
	} `json:"fingerprint_check"`
	NonExistentFileUri string   `json:"non_existent_file_uri"`
	IOCs               []string `json:"iocs"`
	ExceptionURLs      []struct {
		Uri        string `json:"uri"`
		StatusCode int    `json:"status_code"`
	} `json:"exception_urls"`
}

func LoadDetectionRule(configPath string) (*DetectionRule, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rule DetectionRule
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&rule)
	if err != nil {
		return nil, err
	}

	return &rule, nil
}
