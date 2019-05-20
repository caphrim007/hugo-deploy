#!/usr/bin/python
# Copyright (c) 2017 Ansible Project
# Based off of work by Will Thames
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: aws_acm_certificate
short_description: Create certificate request in ACM
description:
  - Create certificate request in ACM
version_added: "2.9"
options:
  domain_name:
    description:
      - The domain name of an ACM certificate to limit the search to
    aliases:
      - name
  validation_method:
    description:
      - The validation method to use for validating the domain
    choices:
      - DNS
      - EMAIL
  idempotency_token:
    description:
      - A string of characters to use to ensure idempotency when requesting a cert.
    default: ansible-aws-acm-certificate-module
requirements:
  - boto3
author:
  - Tim Rupp (@caphrim007)
  - Will Thames (@willthames)
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
- name: Create a new ACM certificate request
  aws_acm_certificate:
    domain_name: "{{ domain_name }}"
'''

RETURN = '''
certificate_arn:
  description: Certificate ARN
  returned: always
  sample: arn:aws:acm:ap-southeast-2:123456789012:certificate/abcd1234-abcd-1234-abcd-123456789abc
  type: str
'''

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import boto3_conn, ec2_argument_spec, get_aws_connection_info
from ansible.module_utils.ec2 import camel_dict_to_snake_dict, AWSRetry, HAS_BOTO3, boto3_tag_list_to_ansible_dict

try:
    import botocore
except ImportError:
    pass  # caught by imported HAS_BOTO3


@AWSRetry.backoff(tries=5, delay=5, backoff=2.0)
def list_certificates_with_backoff(client, statuses=None):
    paginator = client.get_paginator('list_certificates')
    kwargs = dict()
    if statuses:
        kwargs['CertificateStatuses'] = statuses
    return paginator.paginate(**kwargs).build_full_result()['CertificateSummaryList']


@AWSRetry.backoff(tries=5, delay=5, backoff=2.0)
def request_certificate_with_backoff(client, domain_name, validation_method, idempotency_token):
    result = client.request_certificate(
        DomainName=domain_name,
        ValidationMethod=validation_method,
        IdempotencyToken=idempotency_token
    )
    return result['CertificateArn']


@AWSRetry.backoff(tries=5, delay=5, backoff=2.0)
def add_tags_to_certificate(client, certificate_arn, key=None, value=None):
    if key is None:
      return
    response = client.add_tags_to_certificate(
        CertificateArn=certificate_arn,
        Tags=[
          {
            'Key': key,
            'Value': value
          },
        ]
    )


def request_certificate(client, module, validation_method=None, idempotency_token=None, domain_name=None):
    statuses=['PENDING_VALIDATION', 'ISSUED', 'INACTIVE', 'EXPIRED', 'VALIDATION_TIMED_OUT', 'REVOKED', 'FAILED']
    try:
        all_certificates = list_certificates_with_backoff(client, statuses)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg="Couldn't obtain certificates",
                         exception=traceback.format_exc(),
                         **camel_dict_to_snake_dict(e.response))

    certificates = [cert for cert in all_certificates if cert['DomainName'] == domain_name]

    results = []
    if len(certificates) > 0:
      return

    try:
        certificate_arn = request_certificate_with_backoff(client, domain_name, validation_method, idempotency_token)
        add_tags_to_certificate(client, certificate_arn, key='Name', value=domain_name)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg="Couldn't request certificate",
                         exception=traceback.format_exc(),
                         **camel_dict_to_snake_dict(e.response))

    return certificate_arn


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            domain_name=dict(aliases=['name']),
            validation_method=dict(choices=['DNS', 'EMAIL'], default='DNS'),
            idempotency_token=dict(default='ansible'),
        )
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 and botocore are required by this module')

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
    client = boto3_conn(module, conn_type='client', resource='acm',
                        region=region, endpoint=ec2_url, **aws_connect_kwargs)

    certificate_arn = request_certificate(
        client,
        module,
        validation_method=module.params['validation_method'],
        idempotency_token=module.params['idempotency_token'],
        domain_name=module.params['domain_name']
    )
    if certificate_arn:
        module.exit_json(changed=True, certificate_arn=certificate_arn)
    else:
        module.exit_json(changed=False)


if __name__ == '__main__':
    main()