import argparse
import os
import sys

from ruamel.yaml import YAML

from cloudconformity_scanner.scanner import TemplateScanner

# See http https://us-west-2.cloudconformity.com/v1/services | jq '.included[].attributes."risk-level"' | sort -u
RISK_LEVELS = [
    "EXTREME",
    "VERY_HIGH",
    "HIGH",
    "MEDIUM",
    "LOW",
]
LOCAL_CONFIG_FILE = '.cloudconformity-scanner-config.yaml'
HOME_CONFIG_FILE = os.path.join(os.path.expanduser("~"), '.cloudconformity-scanner', 'config.yaml')
API_KEY_ENV_VAR = "CLOUDCONFORMITY_API_KEY"

def main():
    if os.path.isfile(HOME_CONFIG_FILE):
        yaml = YAML()
        with open(HOME_CONFIG_FILE, 'r') as fh:
            home_config = yaml.load(fh)
    else:
        home_config = {}

    api_key = os.environ.get(API_KEY_ENV_VAR, home_config.get('api_key'))
    if api_key is None:
        print("No api key found.", file=sys.stderr)
        print(f"Please configure the {API_KEY_ENV_VAR} environment variable", file=sys.stderr)
        print(f"Or add 'api_key: ...' to {HOME_CONFIG_FILE}", file=sys.stderr)
        exit(os.EX_CONFIG)

    parser = argparse.ArgumentParser(description="Scan CloudFormation template with CloudConformity")
    parser.add_argument('template', nargs='*', default='template.yaml')
    parser.add_argument('--account-id')
    parser.add_argument('--profile-id')
    parser.add_argument('--region', default='eu-west-1')
    parser.add_argument('--exclude-level', action='append')
    parser.add_argument('--exclude-rule', action='append')
    parser.add_argument('--config')
    args = parser.parse_args()
    if args.account_id is not None and args.profile_id is not None:
        print("You cannot use --account-id and --profile-id at the same time")
        exit(os.EX_USAGE)

    config_file = args.config if args.config else LOCAL_CONFIG_FILE
    if os.path.isfile(config_file):
        yaml = YAML()
        with open(config_file, 'r') as fh:
            config_from_file = yaml.load(fh)
    else:
        config_from_file = {}

    account_id = config_from_file.get('account_id')
    profile_id = config_from_file.get('profile_id')
    region = config_from_file.get('region')
    exclude_levels = config_from_file.get('exclude_levels', [])
    exclude_rules = config_from_file.get('exclude_rules', [])

    if args.account_id:
        account_id = args.account_id
    if args.profile_id:
        profile_id = args.profile_id
    if args.region:
        region = args.region
    if args.exclude_level:
        exclude_levels = args.exclude_level

    scanner = TemplateScanner(
        api_key, region,
        account_id=account_id, profile_id=profile_id,
        exclude_levels=exclude_levels, exclude_rules=exclude_rules,
    )

    failure_found = False
    for template_file in args.template:
        template_failure = _scan_file(scanner, template_file)
        if template_failure:
            failure_found = True
    if failure_found:
        exit(1)
    exit(0)


def _scan_file(scanner: TemplateScanner, template_file: str) -> bool:
    with open(template_file, 'r') as fh:
        contents = fh.read()

    bucketed_data = {}
    for item in scanner.scan_template(contents):
        assert item.risk_level in RISK_LEVELS
        if item.risk_level not in bucketed_data:
            bucketed_data[item.risk_level] = []
        bucketed_data[item.risk_level].append(item)

    failure_found = False
    for risk_level in RISK_LEVELS:
        if risk_level not in bucketed_data:
            continue

        failure_found = True
        print(f"[{template_file}] - Found {risk_level} risk issues:")

        findings = sorted(bucketed_data[risk_level], key=lambda x: x.line_number if x.line_number is not None else -1)
        for finding in findings:
            print(
                f"- [{finding.rule_id}] Line {finding.line_number}: {finding.message} ({finding.rule_title}: {finding.status})")
        print("")  # empty line

    return failure_found


if __name__ == '__main__':
    main()
