# policies/naming-policy.rego
package terraform.analysis

deny[reason] {
  input.resource_changes[_].change.after.name == name
  not startswith(name, "rg-")
  reason := sprintf("Resource group name '%s' must start with 'rg-'", [name])
}
