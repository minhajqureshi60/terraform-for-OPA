# main.tf
provider "azurerm" {
  features {}
  subscription_id="d007a5f7-1c80-43e4-adbc-8f0387c82ed9"
}

resource "azurerm_resource_group" "resource" {
  name     = "resource_group"
  location = "eastus"

}

