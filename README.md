# About

This repository contains a standard configuration of Ansible playbooks, roles, and other
content that can be used for the following

- Deploy a small, static website created with hugo (https://gohugo.io/), by publishing
  the static assets to an S3 web-enabled bucket.
- Configure the website with CloudFront and https.
- Configure an AWS Certificate Manager (ACM) certificate verified with Route53.

## Quickstart

Deploy the static site "Release the Kittens" using Ansible

### Step 1

Ensure that you have the following, valid, AWS credentials

* Access key id
* Secret access key

You should put the values of these items in the respective
variables in the `inventory/group_vars/aws/vars.yaml` file,

* `aws_access_key`
* `aws_secret_key`

Alternatively, you can create an Ansible Vault file to store
these values as well.

### Step 2

Ensure that Ansible is installed. This repo was tested with the latest version of
Ansible available at the time; version 2.8.

```
$> pip install ansible
```

### Step 3

Run playbook that bootstraps your Ansible controller. This will ensure that the
libraries necessary to create the cloud infrastructure and deploy content to it
are installed on your system.

```
$> ansible-playbook -i inventory/hosts playbooks/bootstrap-controller.yaml -vvvv
```

Note that the extra `-vvvv` argument is optional, but will greatly assist in
debugging any problems that may arise.

### Step 4

Run playbook that bootstraps your AWS Cloud infrastructure.

This will ensure that the necessary AWS cloud infrastructure is in place to
deploy the website content to.

```
$> ansible-playbook -i inventory/hosts playbooks/bootstrap-infra.yaml -vvvv
```

### Step 5

Run playbook to publish your website content.

If you have pre-configured your CI/CD system to auto-publish
the website content to your S3 bucket, the consider this step
optional.

Regardless, it is helpful to have this playbook in situations where you might have a dev/test bucket that you want to view the content in before it goes to prod.

```
$> ansible-playbook -i inventory/hosts playbooks/deploy-site-content.yaml
```

### Step 6 (optional)

Run playbook to configure AWS ACM certificates on the CloudFront distribution, and validate them agains the Route53 domain `releasethekittens.net`.

Note that for this playbook to work, the aforementioned domain must have been purchased via Route53, and the associated Hosted domain must pre-exist. If you are using Tim's temporary account then both of these cases should already be met.

```
$> ansible-playbook -i inventory/hosts playbooks/bonus.yaml
```

## Playbooks

Playbooks available in this role can be found in the `playbooks/` directory. Each playbook
includes a preamble that explains the purpose of the playbook,, required/optional variables,
and examples of using the playbooks.

The playbooks are summarized below.

* `playbooks/bootstrap-controller.yaml` - Used to setup the Ansible controller
* `playbooks/bootstrap-infra.yaml` - Used to create the AWS cloud infrastructure
* `playbooks/deploy-site-content.yaml` - Used to upload site content to an S3 bucket
* `playbooks/bonus.yaml` - Used to configure AWS ACM certificates on the CloudFront distribution and validate them against the Route53 domain `releasethekittens.net`

## Usage with a virtualenv

If you are using a virtualenv to deploy the infrastructure and content, you will want to
change the `ansible_python_interpreter` value in the `inventory/group_vars/all.yaml`
file.

By default, this is commented out.