
resource "azurerm_subnet" "bastionsubnet" {
  name                 = "AzureBastionSubnet"
  resource_group_name          = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/27"]
}

resource "azurerm_public_ip" "bastionpip" {
  name                = "vnet-demo-ip"
  location            = var.location
  resource_group_name          = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_bastion_host" "bastion" {
  name                = "vnet-demo-bastion"
  location            = var.location
  resource_group_name          = azurerm_resource_group.rg.name

  ip_configuration {
    name                 = "IpConf"
    subnet_id            = azurerm_subnet.bastionsubnet.id
    public_ip_address_id = azurerm_public_ip.bastionpip.id
  }
}