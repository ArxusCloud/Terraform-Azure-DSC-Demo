
resource "azurerm_network_interface" "nics" {
  for_each            = var.dcs
  name                = "nic-${each.key}"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
  ip_configuration {
    name                          = "ip-conf-nic-${each.key}"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Static"
    private_ip_address            = each.value.private_ip_address
  }
}

resource "azurerm_windows_virtual_machine" "dcs" {
  for_each              = var.dcs
  name                  = each.key
  computer_name         = each.key
  custom_data           = base64encode(file("${path.module}/scripts/Configure-DSC.ps1"))
  location              = var.location
  resource_group_name   = var.resource_group_name
  network_interface_ids = [azurerm_network_interface.nics[each.key].id]
  size                  = each.value.vm_size
  admin_username        = each.value.admin_username
  admin_password        = each.value.admin_password
  availability_set_id   = azurerm_availability_set.availabilityset.id


  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }


  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2019-Datacenter"
    version   = "latest"
  }
}



resource "azurerm_virtual_machine_extension" "createMgmtADForest" {
  for_each             = { for k, v in var.dcs : k => v if v.type == "primary" }
  name                 = "createMgmtADForest${each.key}"
  virtual_machine_id   = azurerm_windows_virtual_machine.dcs[each.key].id
  publisher            = "Microsoft.Powershell"
  type                 = "DSC"
  type_handler_version = "2.77"
  depends_on           = [azurerm_windows_virtual_machine.dcs]

  settings           = <<SETTINGS
            {
                "WmfVersion": "latest",
                "configuration": {
                    "url": "https://raw.githubusercontent.com/canada-ca-terraform-modules/terraform-azurerm-caf-adds/v1.1.0/DSC/CreateADRootDC1.ps1.zip",
                    "script": "CreateADRootDC1.ps1",
                    "function": "CreateADRootDC1"
                },
                "configurationArguments": {
                    "DomainName": "${var.ad_domain_name}",
                    "DnsForwarder": "168.63.129.16"
                }
            }
            SETTINGS
  protected_settings = <<PROTECTED_SETTINGS
        {
            "configurationArguments": {
                "adminCreds": {
                    "UserName": "${azurerm_windows_virtual_machine.dcs[each.key].admin_username}",
                    "Password": "${azurerm_windows_virtual_machine.dcs[each.key].admin_password}"
                }
            }
        }
    PROTECTED_SETTINGS
}


resource "azurerm_virtual_machine_extension" "addMgmtADSecondaryDC" {
  for_each             = { for k, v in var.dcs : k => v if v.type == "secondary" }
  name                 = "addMgmtADSecondaryDC${each.key}"
  virtual_machine_id   = azurerm_windows_virtual_machine.dcs[each.key].id
  publisher            = "Microsoft.Powershell"
  type                 = "DSC"
  type_handler_version = "2.77"
  depends_on           = [azurerm_windows_virtual_machine.dcs]
  # depends_on           = [azurerm_virtual_machine_extension.createMgmtADForest]

  settings           = <<SETTINGS
            {
                "WmfVersion": "latest",
           
           
           
                "configuration": {
                    "url": "https://raw.githubusercontent.com/canada-ca-terraform-modules/terraform-azurerm-caf-adds/v1.1.0/DSC/ConfigureADNextDC.ps1.zip",
                    "script": "ConfigureADNextDC.ps1",
                    "function": "ConfigureADNextDC"
                },
                "configurationArguments": {
                    "domainName": "${var.ad_domain_name}",
                    "DNSServer": "${[for k, v in var.dcs : v.private_ip_address if v.type == "primary"][0]}",
                    "DnsForwarder": "${[for k, v in var.dcs : v.private_ip_address if v.type == "primary"][0]}"
                }
            }
            SETTINGS
  protected_settings = <<PROTECTED_SETTINGS
        {
            "configurationArguments": {
                "adminCreds": {
                    "UserName": "${azurerm_windows_virtual_machine.dcs[each.key].admin_username}",
                    "Password": "${azurerm_windows_virtual_machine.dcs[each.key].admin_password}"
                 }
            }
        }
    PROTECTED_SETTINGS
}


resource "azurerm_virtual_machine_extension" "CustomScriptExtension" {
  name                 = "CustomScriptExtension"
  for_each             = var.dcs
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.9"
  virtual_machine_id   = azurerm_windows_virtual_machine.dcs[each.key].id
  settings             = <<SETTINGS
        {   
        "commandToExecute": "powershell -command Set-ExecutionPolicy RemoteSigned -force; powershell -command copy-item \"c:\\AzureData\\CustomData.bin\" \"c:\\AzureData\\CustomData.ps1\";\"c:\\AzureData\\CustomData.ps1\""
        }
  SETTINGS
}
