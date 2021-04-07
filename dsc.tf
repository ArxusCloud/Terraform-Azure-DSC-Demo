resource "random_string" "random" {
  length  = 8
  special = false
}

resource "azurerm_automation_account" "aa" {
  name                = "aa-demo-${random_string.random.result}"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
  sku_name            = "Basic"
}

resource "azurerm_automation_module" "dsc_modules" {
  for_each                = var.dsc_modules
  name                    = each.key
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.aa.name

  module_link {
    uri = each.value
  }
}

resource "azurerm_automation_dsc_configuration" "timezone" {
  name                    = "timezone"
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.aa.name
  location                = var.location
  content_embedded        = "configuration timezone {}"
}

resource "azurerm_automation_dsc_nodeconfiguration" "timezone" {
  name                    = "timezone.localhost"
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.aa.name
  depends_on              = [azurerm_automation_dsc_configuration.timezone]
  content_embedded        = file("${path.cwd}/DSC/timezone/timezone/localhost.mof")
}

resource "azurerm_automation_variable_string" "dnsAddress" {
  name                    = "dscDNSServer"
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.aa.name
  value                   = var.primary_dns_ip
}

resource "azurerm_automation_variable_string" "domainName" {
  name                    = "dscDomainName"
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.aa.name
  value                   = var.ad_domain_name
}

resource "azurerm_automation_credential" "domain_admin" {
  name                    = "dscDomainAdmin"
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.aa.name
  username                = var.domain_admin_username
  password                =  var.domain_admin_password
  description             = "This is a domain credential"
}