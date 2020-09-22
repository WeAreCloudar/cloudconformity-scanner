# CloudConformity Scanner
This tool allows you to run the CloudConformity Template Scanner from the command line

## Usage
You will need to have the `CLOUDCONFORMITY_API_KEY` environment variable set or create
`~/.cloudconformity-scanner/config.yaml` with contents similar to this:

```yaml
api_key: CLOUDCONFORMITY_API_KEY
```

Run `cloudconformity-scanner [file_name]` to scan `file_name`. If no file is give, `template.yaml`
is used.

## Configuration
### Configuration file
You can put some configuration in a configuration file called `.cloudconformity-scanner-config.yaml`
in the same directory where you run the tool. Or you can specify your own file with the `--config`
option.

Example:
```yaml
account_id: CLOUDCONFORMITY_ACCOUNT_ID
profile_id: CLOUDCONFORMITY_PROFILE_ID
region: CLOUDCONFORMITY_REGION
exclude_levels:
  - MEDIUM
exclude_rules:
  - S3-020
  - S3-023
```

### Command line options
Command line options take precedence over the configuration file. Use the `--help` option to see a full list.
