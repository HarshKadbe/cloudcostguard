# Usage Documentation

## CLI Commands

### `cloudcostguard --help`
```
Commands: scan, version
```

### `cloudcostguard scan`
Scans all default services (EC2, EBS, Elastic IP, S3) in the default region.

### `cloudcostguard scan --region <region>`
Scans specified region.

### `cloudcostguard scan --services <comma-separated>`
Scans only specified services. Example: `--services ec2,s3`

### `cloudcostguard scan --format <format>`
Output format: `table` (default), `json`, or `html`.

### `cloudcostguard scan --format json --output <file>`
Write JSON output to file.

### `cloudcostguard scan --format html --output <file>`
Write HTML report to file.

### `cloudcostguard scan --verbose`
Show estimated cost values and debug information.

### `cloudcostguard version`
Show the current version.
