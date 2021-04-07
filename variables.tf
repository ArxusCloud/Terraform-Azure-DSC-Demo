variable "location" {
  description = "Location of the network"
  default     = "westeurope"
}

variable "resource_group_name" {
  default = "dc-demo"
}


variable "vnet_address_space" {
  default = ["10.0.0.0/16"]
}

variable "subnet_ranges" {
  default = ["10.0.0.0/24"]
}
variable "dcs" {
  default = { 
    "dc1" = {
      private_ip_address = "10.0.0.5"
      type = "primary"
      vm_size = "Standard_B2s",
      admin_username = "masterdemouser",
      admin_password = "Sup3rS4fe!Passw0rd",
    },
    "dc2" = {
      private_ip_address = "10.0.0.6"
      type = "secondary"
      vm_size = "Standard_B2s",
      admin_username = "masterdemouser",
      admin_password = "Sup3rS4fe!Passw0rd",
    }
  }
}

variable "vms" {
  default = { 
    "vm1" = {
      private_ip_address = "10.0.0.7"
      vm_size = "Standard_B2s",
      dsc = true,
      NodeConfigurationName = "timezone.localhost"
      admin_username = "masterdemouser",
      admin_password = "Sup3rS4fe!Passw0rd",
    },
    "vm2" = {
      private_ip_address = "10.0.0.8"
      vm_size = "Standard_B2s",
      dsc = false,
      admin_username = "masterdemouser",
      admin_password = "Sup3rS4fe!Passw0rd",
    }
  }
}


variable "ad_domain_name" {
  default = "module.local"
}
variable "domain_admin_username" {
  default = "module\\masterdemouser"
}
variable "domain_admin_password" {
  default = "Sup3rS4fe!Passw0rd"
}
variable "primary_dns_ip" {
  default = "10.0.0.5"
}

variable "dsc_modules" {
  default = {
    #"ComputerManagementDsc" : "https://www.powershellgallery.com/api/v2/package/ComputerManagementDsc/8.4.0",
    "xNetworking" : "https://www.powershellgallery.com/api/v2/package/xNetworking/5.7.0.0"
  }
}