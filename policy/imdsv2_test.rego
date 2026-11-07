package terraform.aws.imdsv2_test

import rego.v1

import data.terraform.aws.imdsv2

plan(after, actions) := {"resource_changes": [{
	"address": "aws_instance.test",
	"type": "aws_instance",
	"change": {"actions": actions, "after": after, "after_unknown": {}},
}]}

test_required_allowed if {
	p := plan({"metadata_options": [{"http_tokens": "required", "http_endpoint": "enabled"}]}, ["create"])
	count(imdsv2.deny) == 0 with input as p
}

test_optional_denied if {
	p := plan({"metadata_options": [{"http_tokens": "optional"}]}, ["create"])
	count(imdsv2.deny) == 1 with input as p
}

test_missing_block_denied if {
	p := plan({"metadata_options": []}, ["create"])
	count(imdsv2.deny) == 1 with input as p
}

test_endpoint_disabled_allowed if {
	p := plan({"metadata_options": [{"http_endpoint": "disabled", "http_tokens": "optional"}]}, ["update"])
	count(imdsv2.deny) == 0 with input as p
}

test_delete_ignored if {
	p := plan({"metadata_options": []}, ["delete"])
	count(imdsv2.deny) == 0 with input as p
}

test_unknown_tokens_denied if {
	p := {"resource_changes": [{
		"address": "aws_instance.test",
		"type": "aws_instance",
		"change": {
			"actions": ["create"],
			"after": {"metadata_options": [{"http_endpoint": "enabled"}]},
			"after_unknown": {"metadata_options": [{"http_tokens": true}]},
		},
	}]}
	count(imdsv2.deny) == 1 with input as p
}

test_launch_template_checked if {
	p := {"resource_changes": [{
		"address": "aws_launch_template.test",
		"type": "aws_launch_template",
		"change": {"actions": ["create"], "after": {"metadata_options": [{"http_tokens": "optional"}]}, "after_unknown": {}},
	}]}
	count(imdsv2.deny) == 1 with input as p
}
