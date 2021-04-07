# $ConfigData = @{
#     AllNodes = @(
#         @{
#             NodeName                    = 'localhost'
#             PSDscAllowPlainTextPassword = $True
#             PSDscAllowDomainUser = $True
#         }
#     )
# }
    
Configuration ComputerJoinDomain
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xNetworking
    Import-DscResource -ModuleName xDSCDomainjoin

    $dscDomainAdmin = Get-AutomationPSCredential -Name 'dscDomainAdmin'
    $dscDomainName = Get-AutomationVariable -Name 'dscDomainName'
    $dnsServer = Get-AutomationVariable -Name 'dscDNSServer'


    Node $AllNodes.NodeName
    {
        
        
        xDnsServerAddress DnsServerAddress
        {
            Address        = $DNSServer
            InterfaceAlias = "Ethernet 2"
            AddressFamily  = 'IPv4'           
        }

        xDSCDomainjoin JoinDomain
        {
            Domain     = $dscDomainName
            Credential = $dscDomainAdmin  
            DependsOn = "[xDnsServerAddress]DnsServerAddress"  
        }
    }
}

#ComputerJoinDomain -ConfigurationData $ConfigData

#Login-AzAccount
#Set-AzContext -SubscriptionId ....
#Start-AzAutomationDscCompilationJob -ResourceGroupName 'dc-demo' -AutomationAccountName 'aa-demo' -ConfigurationName 'ComputerJoinDomain' -ConfigurationData $ConfigData