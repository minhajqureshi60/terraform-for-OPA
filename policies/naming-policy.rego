package terraform.analysis

############################
# Generic naming patterns  #
############################

# Fail when a resource name does not match its convention pattern.
deny[msg] {
  rc := input.resource_changes[_]
  is_create_or_update(rc)

  pattern := regex_for(rc.type)
  pattern != ""                              # only check types we know

  name := rc.change.after.name               # must have a name
  not regex.match(pattern, name)

  msg := sprintf("%s name %q does not match pattern %q (type: %s).",
    [kind_for(rc.type), name, pattern, rc.type])
}

############################
# Specific constraint: Resource Group
############################

deny[msg] {
  rc := input.resource_changes[_]
  rc.type == "azurerm_resource_group"
  name := rc.change.after.name
  not startswith(name, "rg-")
  msg := sprintf("❌ Resource Group name must start with 'rg-': got '%v'", [name])
}

############################
# Azure-specific constraints
############################

# Key Vault: 3-24 chars, start with letter, only [a-z0-9-], must NOT end with '-'
deny[msg] {
  rc := input.resource_changes[_]
  is_create_or_update(rc)
  rc.type == "azurerm_key_vault"
  name := rc.change.after.name
  not regex.match("^[a-z][a-z0-9-]{1,22}[a-z0-9]$", name)
  msg := sprintf("Key Vault name %q must be 3-24 chars, start with a letter, only [a-z0-9-], and must not end with '-'.", [name])
}

# Storage Account: 3-24 lowercase letters/digits, no dashes, require 'st' prefix
deny[msg] {
  rc := input.resource_changes[_]
  is_create_or_update(rc)
  rc.type == "azurerm_storage_account"
  name := rc.change.after.name
  not regex.match("^st[a-z0-9]{1,22}$", name)
  msg := sprintf("Storage Account name %q must be lowercase letters/digits only (no dashes), 3-24 chars total, and start with 'st'.", [name])
}

############################
# Helpers & configuration  #
############################

# Only evaluate creates/updates (destroys have after == null)
is_create_or_update(rc) {
  rc.change.after != null
}

# Friendly kind labels for messages
kind_for(t) := kind {
  mapping := {
    "azurerm_resource_group":            "Resource Group",
    "azurerm_virtual_network":           "Virtual Network",
    "azurerm_subnet":                    "Subnet",
    "azurerm_network_security_group":    "Network Security Group",
    "azurerm_network_interface":         "Network Interface",
    "azurerm_public_ip":                 "Public IP",
    "azurerm_lb":                        "Load Balancer",
    "azurerm_application_gateway":       "Application Gateway",
    "azurerm_key_vault":                 "Key Vault",
    "azurerm_storage_account":           "Storage Account",
    "azurerm_kubernetes_cluster":        "AKS Cluster",
    "azurerm_log_analytics_workspace":   "Log Analytics Workspace",
    "azurerm_container_registry":        "Container Registry",
    "azurerm_route_table":               "Route Table",
  }
  kind := mapping[t]
} else := kind { kind := t }

# Name regex by resource type
regex_for(t) := r {
  r := data.naming.regexes[t]
} else := r {
  defaults := {
    "azurerm_resource_group":          "^rg-[a-z0-9-]+$",
    "azurerm_virtual_network":         "^vnet-[a-z0-9-]+$",
    "azurerm_subnet":                  "^snet-[a-z0-9-]+$",
    "azurerm_network_security_group":  "^nsg-[a-z0-9-]+$",
    "azurerm_network_interface":       "^nic-[a-z0-9-]+$",
    "azurerm_public_ip":               "^pip-[a-z0-9-]+$",
    "azurerm_lb":                      "^lb-[a-z0-9-]+$",
    "azurerm_application_gateway":     "^(agw|appgw)-[a-z0-9-]+$",
    "azurerm_key_vault":               "^kv-[a-z0-9-]{1,22}$",
    "azurerm_storage_account":         "^st[a-z0-9]{1,22}$",
    "azurerm_kubernetes_cluster":      "^aks-[a-z0-9-]+$",
    "azurerm_log_analytics_workspace": "^law-[a-z0-9-]+$",
    "azurerm_container_registry":      "^acr[a-z0-9]{2,47}$",
    "azurerm_route_table":             "^rt-[a-z0-9-]+$",
  }
  r := defaults[t]
}
