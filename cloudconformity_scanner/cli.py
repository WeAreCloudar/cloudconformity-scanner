import argparse
import os
import sys
from dataclasses import dataclass
from typing import Mapping, List, Optional, Iterable

import requests
from ruamel.yaml import YAML, comments

# See http https://us-west-2.cloudconformity.com/v1/services | jq '.included[].attributes."risk-level"' | sort -u
RISK_LEVELS = [
    "EXTREME",
    "VERY_HIGH",
    "HIGH",
    "MEDIUM",
    "LOW",
]
CONFIG_FILE = '.cloudconformity-scanner-config.yaml'
DEBUG = False


def main():
    api_key = os.environ.get('CLOUDCONFORMITY_API_KEY')
    if api_key is None:
        print("Please configure the CLOUDCONFORMITY_API_KEY environment variable", file=sys.stderr)
        exit(os.EX_CONFIG)

    parser = argparse.ArgumentParser(description="Scan CloudFormation template with CloudConformity")
    parser.add_argument('template', nargs='?', default='template.yaml')
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

    config_file = args.config if args.config else CONFIG_FILE
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

    scanner = TemplateScanner(api_key, region, exclude_levels=exclude_levels, exclude_rules=exclude_rules)
    with open(args.template, 'r') as fh:
        contents = fh.read()

    bucketed_data = {}
    for item in scanner.scan_template(contents, account_id, profile_id):
        assert item.risk_level in RISK_LEVELS
        if item.risk_level not in bucketed_data:
            bucketed_data[item.risk_level] = []
        bucketed_data[item.risk_level].append(item)

    failure_found = False
    for risk_level in RISK_LEVELS:
        if risk_level not in bucketed_data:
            continue

        failure_found = True
        print(f"Found {risk_level} risk issues:")

        findings = sorted(bucketed_data[risk_level], key=lambda x: x.line_number if x.line_number is not None else -1)
        for finding in findings:
            print(
                f"- [{finding.rule_id}] Line {finding.line_number}: {finding.message} ({finding.rule_title}: {finding.status})")

    if failure_found:
        exit(1)
    exit(0)


@dataclass
class Finding:
    # From the API
    id: str
    status: str
    risk_level: str
    pretty_risk_level: str
    message: str
    resource: str
    rule_id: str
    rule_title: str
    # Calculated
    line_number: int


class TemplateScanner:
    def __init__(self, api_key, cc_region, exclude_levels: Optional[List] = None, exclude_rules: Optional[List] = None):
        self.api_key = api_key
        self.cc_region = cc_region
        self.exclude_levels = exclude_levels if exclude_levels is not None else []
        self.exclude_rules = exclude_rules if exclude_rules is not None else []

    def scan_template(self, template_contents: str, account_id: str = None, profile_id: str = None) -> Iterable[
        Finding]:
        yaml = YAML()
        source: comments.CommentedMap = yaml.load(template_contents)
        response = requests.post(
            self._api_url,
            headers=self._headers,
            json=self._data(template_contents, account_id, profile_id)
        )
        response.raise_for_status()
        for item in response.json()['data']:
            resource = self._fix(item['attributes']['resource'])
            finding = Finding(
                id=item['id'],
                status=item['attributes']['status'],
                risk_level=item['attributes']['risk-level'],
                pretty_risk_level=item['attributes']['pretty-risk-level'],
                message=item['attributes']['message'],
                resource=resource,
                rule_id=item['relationships']['rule']['data']['id'],
                rule_title=item['attributes']['rule-title'],
                line_number=self._line_number(resource, source)
            )
            if finding.status == "SUCCESS":
                continue
            if finding.risk_level in self.exclude_levels:
                continue
            if finding.rule_id in self.exclude_rules:
                continue
            yield finding

    @property
    def _api_url(self) -> str:
        return f"https://{self.cc_region}-api.cloudconformity.com/v1/template-scanner/scan"

    @property
    def _headers(self) -> Mapping:
        return {
            'Content-Type': 'application/vnd.api+json',
            'Authorization': f'ApiKey {self.api_key}',
        }

    @staticmethod
    def _data(contents: str, account_id: str = None, profile_id: str = None) -> Mapping:
        # account_id and profile_id cannot be both set
        assert account_id is None or profile_id is None

        output = {
            'data': {
                'attributes': {
                    'type': 'cloudformation-template',
                    'contents': contents
                }
            }
        }
        if account_id is not None:
            output['data']['attributes']['accountId'] = account_id
        if profile_id is not None:
            output['data']['attributes']['profileId'] = profile_id

        return output

    @staticmethod
    def _line_number(resource: str, source: Mapping) -> Optional[int]:
        try:
            return source['Resources'][resource].lc.line
        except KeyError:
            DEBUG and print(f"Couldn't find {resource} in the template. No line number added", file=sys.stderr)
            return None

    @staticmethod
    def _fix(resource: str) -> str:
        # arn:aws:cloudtrail:us-east-1:123456789012:trail/RESOURCE-RANDOM
        if resource.startswith('arn:aws:cloudtrail:us-east-1:123456789012:trail/'):
            return resource.split('/')[1].split('-')[0]
        # arn:aws:sns:us-east-1:123456789012:RESOURCE
        if resource.startswith('arn:aws:sns:us-east-1:123456789012'):
            return resource.split(':')[-1]
        return resource


if __name__ == '__main__':
    main()
