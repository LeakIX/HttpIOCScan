# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HttpIOCScan (formerly GenericIOCScan/CitrixIOCScan) is a configurable security scanning tool for detecting webshell indicators of compromise (IOCs) across different software platforms. It performs mass scanning with rate-limiting and abnormal reply detection to identify potentially compromised systems.

The tool uses configurable detection rules to:
1. **Fingerprint software** - Identify the target software type
2. **Establish baselines** - Determine normal response codes for non-existent files
3. **Scan for IOCs** - Check known webshell paths for abnormal responses
4. **Filter false positives** - Skip known legitimate variations

Originally designed for Citrix ADC/NetScaler but now supports multiple software types through JSON configuration files.

## Architecture

The application follows a concurrent producer-consumer pattern:

- **Main entry point**: `cmd/CitrixIOCScan/main.go` - handles command-line arguments and orchestrates the scanning
- **Core scanning logic**: `HostScanner.go` - implements the generic scanning logic with configurable rules
- **HTTP client configuration**: `SaneHttpClient.go` - provides a properly configured HTTP client for security scanning
- **Configuration system**: `ScannerConfig.go` - defines detection rules and loads configurations
- **Legacy IOC database**: `url_list.txt` - backward compatibility for Citrix-specific IOCs
- **Example configurations**: `examples/` - sample detection rules for different software types

### Key Components

1. **HostScanner**: Manages concurrent scanning of individual hosts
   - **Software fingerprinting**: Tests if target matches configured software signatures
   - **Baseline establishment**: Determines normal response codes using test URLs
   - **IOC scanning**: Iterates through rule-specific IOC lists looking for abnormal responses
   - **False positive filtering**: Applies rule-specific exclusions
   - **Error handling**: Implements connection error thresholds and rate limiting

2. **DetectionRule**: Configurable rule structure containing:
   - **Fingerprint**: URL and content pattern to identify software
   - **Baseline test URL**: Template for generating non-existent file URLs (with %d placeholder)
   - **IOC list**: Suspected webshell paths to check
   - **Exclusions**: Known false positives to skip

3. **HTTP Client**: Configured for security scanning with:
   - 5-second timeouts
   - Disabled keep-alives to avoid detection
   - TLS verification disabled (for scanning compromised systems)
   - Redirect prevention
   - Limited response header size

## Common Commands

### Building
```bash
# Build with CGO disabled for static binary
CGO_ENABLED=0 go build -o HttpIOCScan ./cmd/HttpIOCScan

# Install directly from GitHub
go install github.com/leakix/HttpIOCScan/cmd/HttpIOCScan@latest
```

### Running
```bash
# Basic usage - Citrix scanning with default rules
./HttpIOCScan input.json config.json > results.json

# Advanced usage - multi-software scanning with custom config
./HttpIOCScan input.json config.json > results.json

# Example with provided configurations
./HttpIOCScan input.json examples/citrix-config.json > results.json
```

### Testing
```bash
# Run Go tests
go test ./...

# Test with verbose output
go test -v ./...
```

### Code Quality
```bash
# Format code
go fmt ./...

# Vet code for potential issues
go vet ./...

# Run staticcheck if available
staticcheck ./...
```

## Input/Output Format

### Input Format (JSON Lines)
```json
{"ip":"127.0.0.1","port":"443","host":"localhost.localdomain"}
{"ip":"127.0.1.1","port":"443","host":"localhost.localdomain"}
```

### Output Format
Results are output as L9 format JSON events containing:
- Target information (IP, port, host)
- SSL certificate details if available
- Detected IOC details and severity
- Event metadata for integration with security platforms

## Development Notes

- The tool uses `github.com/LeakIX/l9format` for structured security event output
- Concurrent scanning is limited to 1000 goroutines by default (`MaxRoutines`)
- Rate limiting includes randomized delays (1-1.9 seconds) between requests
- Connection error threshold is 5 errors before stopping scan of a host
- Always assumes HTTPS connections
- **Configuration format**: JSON-based detection rules allow adding new software types
- **Backward compatibility**: Legacy `url_list.txt` still supported for Citrix-only scanning
- **Extensibility**: New software types can be added by creating detection rules without code changes

## Adding New Software Detection

1. **Identify software fingerprint**: Find a unique URL/content combination
2. **Determine baseline URL**: Template for non-existent files (use %d for random number)
3. **Collect IOC paths**: Known webshell locations for that software
4. **Test exclusions**: Identify any false positive patterns
5. **Create rule**: Add to configuration file following the JSON schema

## Security Considerations

This is a defensive security tool designed to detect compromised systems. The codebase:
- Uses TLS verification bypass only for scanning potentially compromised targets
- Implements rate limiting to avoid overwhelming target systems
- Focuses on detection rather than exploitation
- Outputs structured data for security operations integration