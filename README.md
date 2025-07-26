# CitrixIOCScan

Tool to mass scan a bunch for Citrix servers with rate-limiting and abnormal reply detection.

## Installation

```shell
$ go install github.com/leakix/CitrixIOCScan@latest
```

or build:

```shell
$ CGO_ENABLED=0 go build -o CitrixIOCScan ./
```

## Usage

1. Create a JSON file as follow:

```json lines
{"ip":"127.0.0.1","port":"443","host":"localhost.localdomain"}
{"ip":"127.0.1.1","port":"443","host":"localhost.localdomain"}
....
```

2. Run

```shell
$ CitrixIOCScan url_list.txt input.json > results.json
```

## Limitations

- Currently, always assumes HTTPS
- This can be made generic for future research
