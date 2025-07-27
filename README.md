# HttpIOCScan

Configurable tool to scan for webshell indicators of compromise (IOCs) across HTTP/HTTPS services with rate-limiting and abnormal reply detection. Uses JSON configuration files to define detection rules for different software platforms.

## Installation

```shell
$ go install github.com/leakix/HttpIOCScan/cmd/HttpIOCScan@latest
```

or build:

```shell
$ CGO_ENABLED=0 go build -o HttpIOCScan ./cmd/HttpIOCScan
```

## Usage

1. Create a JSON file with targets:

```json lines
{"ip":"127.0.0.1","port":"443","host":"localhost.localdomain"}
{"ip":"127.0.1.1","port":"443","host":"localhost.localdomain"}
....
```

2. Run with a detection rule configuration:

```shell
$ ./HttpIOCScan input.json config.json > results.json
```

### Command Line Options

```shell
$ ./HttpIOCScan --help
Usage: HttpIOCScan <input> <config>

Arguments:
  <input>     JSON file containing targets to scan
  <config>    JSON configuration file with detection rules

Flags:
  -h, --help                Show context-sensitive help.
  -r, --routines=1000       Number of concurrent scanning routines
  -d, --delay=1s            Base delay between requests (randomized +0-900ms)
```

**Examples:**
```shell
# Use custom number of routines and delay
$ ./HttpIOCScan -r 500 -d 2s input.json citrix-config.json > results.json

# Fast scanning with minimal delay  
$ ./HttpIOCScan --routines 100 --delay 100ms input.json sharepoint-config.json > results.json
```

### Example Configurations

See the `examples/` directory for sample detection rules:
- `citrix-config.json` - Citrix ADC/NetScaler detection
- `sharepoint-config.json` - Microsoft SharePoint detection

### Configuration Format

Detection rules are defined in JSON format matching the DetectionRule struct:

```json
{
  "name": "Software Name",
  "description": "Detection description",
  "fingerprint_check": {
    "uri": "/path/to/identify/software",
    "expected_content": "expected string in response"
  },
  "non_existent_file_uri": "/path/to/nonexistent%d.ext",
  "iocs": [
    "/suspected/webshell/path1",
    "/suspected/webshell/path2"
  ],
  "exception_urls": [
    {
      "uri": "/known/exception/pattern",
      "status_code": 404
    }
  ]
}
```

**Schema Details:**
- `name`: Human-readable name for the software being detected
- `description`: Brief description of what this rule detects
- `fingerprint_check.uri`: URL path used to identify the target software
- `fingerprint_check.expected_content`: String that should appear in the response to confirm software match
- `non_existent_file_uri`: Template URL for testing baseline responses (use `%d` placeholder for random number)
- `iocs`: Array of suspected webshell/IOC paths to check
- `exception_urls`: Array of known false positives to skip, each with `uri` pattern and expected `status_code`

## Features

- **Single rule per run**: Focused scanning with one detection rule at a time
- **Rate limiting**: Built-in delays to avoid overwhelming targets
- **Fingerprinting**: Automatic software identification before scanning
- **Baseline detection**: Establishes normal response codes for non-existent files
- **Exception handling**: Skip URLs with expected status codes
- **Concurrent scanning**: Configurable number of parallel scanners

## Limitations

- Currently assumes HTTPS connections
- Requires JSON configuration file (no default rules)
- One detection rule per execution