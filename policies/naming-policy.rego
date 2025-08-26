package terraform.analysis

# Fail on violations. conftest prints deny[] and exits non-zero.
deny[msg] {
  rc := input.resource_changes[_]
  is_create_or_update(rc)
  pattern := regex_for(rc.type)
  pattern != ""                                   # only check types we know
  name := rc.change.after.name                    # resource must have "name"
  not regex.match(pattern, name)
  kind := kind_for(rc.type)
  msg := sprintf("%s name %q does not match pattern %q (type: %s).",
                 [kind, name, pattern, rc.type])
}

# Extra Azure constraints for specific services
deny[msg] {
  rc := input.resource_changes[_]
  is_create_or_update(rc)
  rc.type == "azurerm_key_vault"
  name := rc.change.after.name
  (endswith(name, "-")  # KV names can't end with '-'
   or not regex.match("^[a-z][a-z0-9-]{2,23}$", name))  # 3–24, start w/ letter
  msg := sprintf("Key Vault name %q must be 3–24 chars, start with a letter, " ||
                 "contain only [a-z0-9-], and not end with '-'.", [name])
}

deny[msg] {
  rc := input.resource_changes[_]
  is_create_or_update(rc)
  rc.type == "azurerm_storage_account"
  name := rc.change.after.name
  # SA: 3–24 lowercase letters/digits, no dashes. Also require 'st' prefix by default.
  not (regex.match("^st[a-z0-9]{2,22}$", name) and regex.match("^[a-z0-9]{3,24}$", name))
  msg := sprintf("Storage Account name %q must be lowercase letters/digits, " ||
                 "3–24 chars, no dashes, and start with 'st'.", [name])
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
    "azurerm_key_vault":               "^kv-[a-z0-9-]{1,22}$",     # plus extra rule above
    "azurerm_storage_account":         "^st[a-z0-9]{2,22}$",       # plus extra rule above
    "azurerm_kubernetes_cluster":      "^aks-[a-z0-9-]+$",
    "azurerm_log_analytics_workspace": "^law-[a-z0-9-]+$",
    "azurerm_container_registry":      "^acr[a-z0-9]{2,47}$",      # 5–50 alnum, we require 'acr'
    "azurerm_route_table":             "^rt-[a-z0-9-]+$",
  }
  r := defaults[t]
}
