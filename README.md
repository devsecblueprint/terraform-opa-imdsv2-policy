# OPA + Terraform: Enforce IMDSv2 on EC2

An OPA policy that evaluates a Terraform plan (JSON) and denies any `aws_instance`
or `aws_launch_template` that does not enforce IMDSv2.

A resource passes if either:
- `metadata_options.http_tokens = "required"`, or
- `metadata_options.http_endpoint = "disabled"`

It fails if `metadata_options` is missing (provider default allows IMDSv1), if
`http_tokens = "optional"`, or if `http_tokens` is unknown at plan time.
Resources being deleted are ignored.

## Layout

```
policy/imdsv2.rego         policy (package terraform.aws.imdsv2)
policy/imdsv2_test.rego    unit tests
examples/compliant/        passes
examples/noncompliant/     fails (2 violations)
```

## Prerequisites

- Terraform >= 1.5
- OPA (tested with 1.17.0)

The examples use mock AWS credentials and skip validation, so no AWS account is needed.

## 1. Run the policy unit tests

```sh
opa test policy -v
```

## 2. Check the compliant example

```sh
cd examples/compliant

terraform init -backend=false
terraform plan -out=tfplan.bin
terraform show -json tfplan.bin > tfplan.json

# Prints "undefined" when there are no violations
opa eval --fail-defined --format pretty \
  -d ../../policy/imdsv2.rego -i tfplan.json \
  'data.terraform.aws.imdsv2.deny[_]'
echo $?   # 0 = pass
```

## 3. Check the non-compliant example

```sh
cd examples/noncompliant

terraform init -backend=false
terraform plan -out=tfplan.bin
terraform show -json tfplan.bin > tfplan.json

opa eval --fail-defined --format pretty \
  -d ../../policy/imdsv2.rego -i tfplan.json \
  'data.terraform.aws.imdsv2.deny[_]'
echo $?   # 1 = violations found
```

Expected output:

```
aws_instance.no_block must set metadata_options.http_tokens = "required" to enforce IMDSv2 (found "<unset: defaults to optional>")
aws_instance.optional must set metadata_options.http_tokens = "required" to enforce IMDSv2 (found "optional")
```

## Useful variations

Summary result (`allow`, `violations`, `checked`):

```sh
opa eval --format pretty \
  -d policy/imdsv2.rego -i examples/noncompliant/tfplan.json \
  'data.terraform.aws.imdsv2.result'
```

Use your own configuration instead of the examples:

```sh
cd path/to/your/terraform
terraform init
terraform plan -out=tfplan.bin
terraform show -json tfplan.bin > tfplan.json
opa eval --fail-defined --format pretty \
  -d /path/to/opa-terraform-example/policy/imdsv2.rego -i tfplan.json \
  'data.terraform.aws.imdsv2.deny[_]'
```

Format and validate:

```sh
opa fmt -w policy
opa check policy
terraform fmt -recursive examples
terraform -chdir=examples/compliant validate
```

Clean up generated files:

```sh
rm -rf examples/*/.terraform examples/*/tfplan.bin examples/*/tfplan.json examples/*/.terraform.lock.hcl
```
