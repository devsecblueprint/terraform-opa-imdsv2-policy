# =============================================================================
# IMDSv2 enforcement policy for Terraform plans
# =============================================================================
#
# PURPOSE
#   Deny any EC2 instance or launch template whose Terraform plan would leave
#   IMDSv1 enabled. IMDSv1 is vulnerable to SSRF-based credential theft, so
#   we require IMDSv2 (session-token based) or no metadata service at all.
#
# INPUT  (the `input` document, type: object)
#   The JSON produced by:
#     terraform plan -out=tfplan.bin
#     terraform show -json tfplan.bin > tfplan.json
#   Only `input.resource_changes` is used (type: array of objects).
#   Each element looks like:
#     {                                                  <- object
#       "address": "aws_instance.web",                   <- string
#       "type":    "aws_instance",                       <- string
#       "change": {                                      <- object
#         "actions":       ["create"],                   <- array of strings
#         "after":         { "metadata_options": [ {     <- array of 1 object
#                              "http_tokens": "required" <- string
#                          } ] },
#         "after_unknown": { "metadata_options": [ {     <- array of 1 object
#                              "http_tokens": true       <- boolean
#                          } ] }
#       }
#     }
#
# OUTPUT
#   data.terraform.aws.imdsv2.deny    type: set of strings (violation messages)
#   data.terraform.aws.imdsv2.result  type: object {allow: boolean,
#                                                   violations: set,
#                                                   checked: number}
#
# COMPLIANT WHEN (either is sufficient)
#   - metadata_options.http_tokens   == "required"  (IMDSv2 only), or
#   - metadata_options.http_endpoint == "disabled"  (no IMDS at all)
#
# REGO CONSTRUCTS USED (quick key)
#   complete rule      `name := value`          exactly one value
#   partial set rule   `name contains x if {}`  builds a set, one member per match
#   function           `name(arg) := value`     takes arguments, returns a value
#   boolean function   `name(arg) if {}`        true, or undefined (never false)
#   set literal        `{"a", "b"}`             unordered, unique members
#   array literal      `["a", "b"]`             ordered, indexable with [0]
#   object literal     `{"k": v}`               key/value map
#   `some x in coll`   iteration (NOT a comprehension; it loops over a
#                      collection and binds x for the rest of the rule body)
# =============================================================================

package terraform.aws.imdsv2

# rego.v1 enables the modern syntax (`if`, `contains`, `in`) and strict checks.
# It is the default in OPA 1.x, but stays explicit for older OPA versions.
import rego.v1

# -----------------------------------------------------------------------------
# checked_types
#   TYPE: complete definition whose value is a SET LITERAL of strings.
#   Resource types this policy inspects. Add more here if needed. Auto Scaling
#   groups don't need listing, because they inherit metadata_options from the
#   launch template they reference.
# -----------------------------------------------------------------------------
checked_types := {"aws_instance", "aws_launch_template"}

# -----------------------------------------------------------------------------
# managed_resources
#   TYPE: PARTIAL SET RULE. Evaluates to a set of objects (resource_changes
#   entries). Each time the body succeeds, `rc` is added to the set.
#   This is not a set comprehension (`{x | ...}`); it is the rule-head form
#   `contains x if {...}`, which produces the same kind of result.
#
#   Included: checked types whose planned actions include create or update.
#   Excluded: "delete" (resource going away) and "no-op"/"read" (unchanged).
#   A replacement shows up as ["delete","create"], which still matches "create".
# -----------------------------------------------------------------------------
managed_resources contains rc if {
	some rc in input.resource_changes # iterate an ARRAY of objects; rc = object
	rc.type in checked_types # `in` tests membership: string in SET
	some action in rc.change.actions # iterate an ARRAY of strings; action = string
	action in {"create", "update"} # membership test against a SET LITERAL
}

# -----------------------------------------------------------------------------
# metadata_options(rc)
#   TYPE: FUNCTION (with `else`). Argument: object. Returns: object.
#   In plan JSON, a nested block is an ARRAY with one element, so `some opts in`
#   iterates the array and binds that single OBJECT. If the block is absent or
#   the array is empty, the first body is undefined and the `else` returns {}
#   (an empty OBJECT LITERAL). The provider default then applies, which allows
#   IMDSv1 ("optional"), so downstream checks will fail as intended.
# -----------------------------------------------------------------------------
metadata_options(rc) := opts if {
	some opts in rc.change.after.metadata_options
} else := {}

# -----------------------------------------------------------------------------
# endpoint_disabled(opts)
#   TYPE: BOOLEAN FUNCTION. Argument: object. Returns: true, or undefined.
#   True when the instance metadata service is switched off entirely.
#   With no IMDS there is no IMDSv1 exposure, so this is treated as compliant.
#   `==` compares a string field to a string literal.
# -----------------------------------------------------------------------------
endpoint_disabled(opts) if opts.http_endpoint == "disabled"

# -----------------------------------------------------------------------------
# tokens_unknown(rc)
#   TYPE: BOOLEAN FUNCTION. Argument: object. Returns: true, or undefined.
#   True when http_tokens cannot be determined at plan time, for example when it
#   is computed from a value only known after apply. Terraform marks such
#   attributes as the BOOLEAN `true` in `after_unknown`. The path indexes an
#   ARRAY with [0] to reach its first OBJECT. We cannot prove compliance for
#   unknown values, so the caller treats this as a failure (fail closed).
# -----------------------------------------------------------------------------
tokens_unknown(rc) if {
	rc.change.after_unknown.metadata_options[0].http_tokens == true
}

# -----------------------------------------------------------------------------
# enforces_imdsv2(rc)
#   TYPE: BOOLEAN FUNCTION with two bodies. Argument: object.
#   Returns: true, or undefined.
#   Two bodies with the same name act as a logical OR:
#   the function is true if EITHER body is true.
# -----------------------------------------------------------------------------

# Path 1: tokens are explicitly required, and that value is known (not computed).
# Lines in a body are ANDed. `not` negates (succeeds when the call is undefined).
enforces_imdsv2(rc) if {
	metadata_options(rc).http_tokens == "required" # string == string
	not tokens_unknown(rc) # negated boolean function call
}

# Path 2: the metadata endpoint is disabled, so IMDSv2 enforcement is moot.
# One-line body form: the function is true when endpoint_disabled(...) is true.
enforces_imdsv2(rc) if endpoint_disabled(metadata_options(rc))

# -----------------------------------------------------------------------------
# deny
#   TYPE: PARTIAL SET RULE. Evaluates to a set of strings (violation messages),
#   one per non-compliant resource. Empty set means the plan passes. Consumers
#   should treat any member as a failure (the README uses
#   `opa eval --fail-defined` on `deny[_]`).
#
#   The message reports the actual http_tokens value found. If the attribute is
#   unset, object.get (builtin: object, key, default) supplies a placeholder
#   string explaining the provider default.
# -----------------------------------------------------------------------------
deny contains msg if {
	some rc in managed_resources # iterate a SET of objects
	not enforces_imdsv2(rc) # keep only those failing both compliance paths
	msg := sprintf(
		"%s must set metadata_options.http_tokens = \"required\" to enforce IMDSv2 (found %q)", # local variable; sprintf returns a string
		[rc.address, object.get(metadata_options(rc), "http_tokens", "<unset: defaults to optional>")], # ARRAY LITERAL of 2 strings (the values fed to %s and %q)
	)
}

# -----------------------------------------------------------------------------
# result
#   TYPE: COMPLETE RULE whose value is an OBJECT LITERAL with three fields.
#   Convenience summary for dashboards or CI tooling:
#     allow      BOOLEAN. true when there are zero violations (count() of a
#                set returns a number, compared with ==)
#     violations SET of strings. The full deny set
#     checked    NUMBER. How many resources were evaluated (0 means nothing
#                relevant in the plan, which is a pass but worth noticing in CI)
# -----------------------------------------------------------------------------
result := {
	"allow": count(deny) == 0,
	"violations": deny,
	"checked": count(managed_resources),
}
