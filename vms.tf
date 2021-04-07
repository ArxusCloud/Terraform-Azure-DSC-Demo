

resource "azurerm_network_interface" "vmnics" {
  for_each            = var.vms
  name                = "nic-${each.key}"
  location            = var.location
  resource_group_name          = azurerm_resource_group.rg.name
  ip_configuration {
    name                          = "ip-conf-nic-${each.key}"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Static"
    private_ip_address            = each.value.private_ip_address
  }
}

resource "azurerm_windows_virtual_machine" "vms" {
  for_each              = var.vms
  name                  = each.key
  computer_name         = each.key
  location              = var.location
  resource_group_name   = var.resource_group_name
  network_interface_ids = [azurerm_network_interface.vmnics[each.key].id]
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



resource "azurerm_virtual_machine_extension" "vmsdsc" {
  for_each             = { for k, v in var.vms : k => v if v.dsc }
  name                 = "dsc${each.key}"
  virtual_machine_id   = azurerm_windows_virtual_machine.vms[each.key].id
  publisher            = "Microsoft.Powershell"
  type                 = "DSC"
  type_handler_version = "2.77"
  depends_on           = [azurerm_windows_virtual_machine.vms, azurerm_automation_dsc_nodeconfiguration.timezone]
  tags = {
    "AutomationAccountARMID" = azurerm_automation_account.aa.id
  }

  settings           = <<SETTINGS
            {
                "configurationArguments": {
                    "RegistrationUrl": "${azurerm_automation_account.aa.dsc_server_endpoint}",
                    "NodeConfigurationName": "${each.value.NodeConfigurationName}",
                    "ConfigurationMode": "applyAndMonitor",
                    "RebootNodeIfNeeded": false,
                    "ActionAfterReboot": "continueConfiguration",
                    "AllowModuleOverwrite": false,
                    "ConfigurationModeFrequencyMins": 15,
                    "RefreshFrequencyMins": 30
                }
            }
            SETTINGS
  protected_settings = <<PROTECTED_SETTINGS
        {
             "configurationArguments": {
                "RegistrationKey": {
                    "userName": "NOT_USED",
                    "Password": "${azurerm_automation_account.aa.dsc_primary_access_key}"
                }
            }
        }
    PROTECTED_SETTINGS
}
