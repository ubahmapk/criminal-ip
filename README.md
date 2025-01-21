# Criminal IP API

Python script to access the Criminal IP API

The goal will be to integrate this code into the [Sooty](https://github.com/TheresAFewConors/Sooty) project as a feature.

Requires an API key from https://criminalip.io

## Usage

```
Usage: criminal-ip [OPTIONS] [IP]

 Python client for Criminal IP API
 Requires an API key from https://criminalip.io
 The API key should be provided via the CRIMINAL_IP_API_KEY environment variable.

╭─ Arguments ───────────────────────────────────────────────────────────────────────────╮
│   ip      [IP]  IP address to check                                                   │
╰───────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ─────────────────────────────────────────────────────────────────────────────╮
│ --api-key  -k      TEXT     Criminal IP API Key [env var: CRIMINAL_IP_API_KEY]        │
│ --account  -a               Print account info and exit                               │
│ --verbose  -v      INTEGER  Verbose mode. Repeat for increased verbosity [default: 0] │
│ --version  -V               Show version and exit                                     │
│ --help     -h               Show this message and exit.                               │
╰───────────────────────────────────────────────────────────────────────────────────────╯
```
