import sys
from dataclasses import dataclass
from typing import Optional, List, Iterable, Mapping

import requests
from ruamel.yaml import YAML, comments

DEBUG = False


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
    def __init__(
            self, api_key, cc_region,
            account_id: Optional[str] = None, profile_id: Optional[str] = None,
            exclude_levels: Optional[List] = None, exclude_rules: Optional[List] = None,
    ):
        self.api_key = api_key
        self.cc_region = cc_region
        self.account_id = account_id
        self.profile_id = profile_id
        self.exclude_levels = exclude_levels if exclude_levels is not None else []
        self.exclude_rules = exclude_rules if exclude_rules is not None else []

    def scan_template(
            self, template_contents: str,
            override_account_id: Optional[str] = None, override_profile_id: Optional[str] = None,
    ) -> Iterable[Finding]:
        account_id = override_account_id if override_account_id is not None else self.account_id
        profile_id = override_profile_id if override_profile_id is not None else self.profile_id

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
