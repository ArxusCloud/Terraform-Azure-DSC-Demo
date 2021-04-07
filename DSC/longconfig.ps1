configuration Main
{
param
(
[string]$JukeboxID = "localhost",
[string]$nodeName = $env:COMPUTERNAME,
[string]$VNCKey
)

#Import-DscResource -Name 'xRemoteFile' -ModuleName '.\xPSDesiredStateConfiguration'
<# xPSDesiredStateConfiguration containes….
xDscWebService, xWindowsProcess, xService, xPackage
xArchive, xRemoteFile, xPSEndpoint, xWindowsOptionalFeature
#>

$SourceFiles = "$env:SystemDrive\SourceFiles"
$PublicStorageSourceContainer = 'https://msmarcsg.blob.core.windows.net/deployment'

Node $env:COMPUTERNAME
  {
    File SourceFiles 
    {
        DestinationPath = $SourceFiles
        Ensure = 'Present'
        Type = 'Directory'
    }
    File PHPFiles
    {
        SourcePath = "$SourceFiles\PHP\PHP-7.0.13"
        DestinationPath = "$env:SystemDrive\PHP\7.0.13"
        Ensure = 'Present'
        Type = 'Directory'
        Recurse = $true
        DependsOn = "[Script]UnEncryptSourceFiles"
    }
    File WinCache
    {
        SourcePath = "$SourceFiles\PHP\WinCache 2.0.0.8\php_wincache.dll"
        DestinationPath = "$env:SystemDrive\PHP\7.0.13\ext"
        Ensure = 'Present'
        Type = 'File'
        DependsOn = "[File]PHPFiles"
    }


################################################################################
##################     Packages, Software Installation
################################################################################
#region Packages
    Package InstallVNCServer
    {
        Ensure = "Present"
        Path = "$SourceFiles\RealVNC\VNC-Server-5.3.2-Windows-en-64bit.msi"
        Name = "VNC Server 5.3.2"
        ProductId = "{BD3BF59A-3CD6-49B3-A166-E57BF55FF959}"
        #DependsOn = "[Script]UnEncryptSourceFiles"
        #Arguments = "ADDLOCAL=ALL"
        DependsOn = "[Script]UnEncryptSourceFiles"
    }

    Package PHPManagerForIIS
    { 
        Ensure = "Present"
        Path = "$SourceFiles\PHP\PHP Manager 1.4.0\PHPManagerForIIS-1.4.0-x64.msi"
        ProductId = "{E851486F-1FE2-44F0-85ED-F969088A68EE}"
        Name = "PHP Manager 1.4 for IIS 10"
        DependsOn = @("[Script]UnEncryptSourceFiles","[WindowsFeature]WAS-NET-Environment")
    }

    Package InstallAzCopy
    {
        Ensure = "Present"
        Path  = "$SourceFiles\MicrosoftAzureStorageTools.msi"
        Name = "Microsoft Azure Storage Tools – v6.1.0"
        ProductId = "{1D24B7AC-AFB4-44D4-928B-5CB14ABF4839}"
        #Arguments = "ADDLOCAL=ALL"
        DependsOn = "[Script]DownloadAzCopy"
    }
#endregion

################################################################################
##################     Windows Features
################################################################################
#region Windows Features
    foreach ($Feature in @("Web-Server","Web-Common-Http","Web-Static-Content", ` 
            "Web-Default-Doc","Web-Dir-Browsing","Web-Http-Errors",` 
            "Web-Health","Web-Http-Logging","Web-Log-Libraries",` 
            "Web-Request-Monitor","Web-Security","Web-Filtering",`
            "Web-Stat-Compression","Web-Http-Redirect","Web-Mgmt-Tools",`
            "WAS","WAS-Process-Model","WAS-NET-Environment","WAS-Config-APIs","Web-CGI"))
        {
    WindowsFeature $Feature
    {
      Name = $Feature
      Ensure = "Present"
    }
}
#endregion

################################################################################
##################     Scripts
################################################################################
#region Scripts

   Script DownloadAzCopy
    {
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            Test-Path "$using:SourceFiles\MicrosoftAzureStorageTools.msi"
        }
        SetScript = {
            $source = "$using:PublicStorageSourceContainer/AzCopy/MicrosoftAzureStorageTools.msi"
            $dest = "$using:SourceFiles\MicrosoftAzureStorageTools.msi"
            Invoke-WebRequest $source –OutFile $dest
        }
		GetScript = { # should return a hashtable representing the state of the current node
            $result = Test-Path "$using:SourceFiles\MicrosoftAzureStorageTools.msi"
			@{
				"Downloaded" = $result
			}
		}
        DependsOn = "[File]SourceFiles"
    }
   
   Script CopyEncryptedSourceFiles
    {
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            Test-Path "$using:SourceFiles\Scripts"
        }
        SetScript = {
            $azPath = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\AzCopy"
            Remove-Item –Path $env:USERPROFILE\AppData\Local\Microsoft\Azure\AzCopy\*.* –Force –ErrorAction SilentlyContinue
            $prog ="${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\AzCopy\AzCopy.exe"
            $AzsrcUri = $using:PublicStorageSourceContainer
            $TargetDir = "$using:SourceFiles"
            $params=@("/source:$AzsrcUri /Dest:$TargetDir /s /y")
            Start-Process $prog $params –Wait

        }
		GetScript = { # should return a hashtable representing the state of the current node
            $result = Test-Path "$using:SourceFiles\Scripts"
			@{
				"Downloaded" = $result
			}
		}
        DependsOn = "[Package]InstallAzCopy"
    }

# Un-Encrypt Scripts
    Script UnEncryptSourceFiles
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            if (!(Get-ChildItem "$using:SourceFiles" –Recurse –Filter *.encrypted)) {return $True}
			else {return $False}
        }
        SetScript = {
		# change the following two secret phrases
		$salt = "Marc01"
		$init = "Marc6491649137"

		# supply a strong password
		$CertThumbprint = (Get-ChildItem cert:\LocalMachine\My |
        Where-Object –FilterScript {$_.PrivateKey -and ($_.EnhancedKeyUsageList.FriendlyName -eq 'Document Encryption') -and ($_.Issuer -notmatch 'microsoft.com')}).Thumbprint
		$password = $CertThumbprint
		
		function Decrypt-File([string]$encryptedFile, [string]$decryptedFile)
			{
			if($decryptedFile -eq $null -or $decryptedFile -eq "")
			{
				$decryptedFile = $encryptedFile
			}

			$rijndaelCSP = New-Object System.Security.Cryptography.RijndaelManaged
			$pass = [System.Text.Encoding]::UTF8.GetBytes($password)
			$salt = [System.Text.Encoding]::UTF8.GetBytes($salt)
	 
			$rijndaelCSP.Key = (New-Object Security.Cryptography.PasswordDeriveBytes $pass, $salt, "SHA1", 5).GetBytes(32) #256/8
			$rijndaelCSP.IV = (New-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($init) )[0..15]
	 
			$decryptor = $rijndaelCSP.CreateDecryptor()

			$inputFileStream = New-Object System.IO.FileStream($encryptedFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
			$decryptStream = New-Object Security.Cryptography.CryptoStream $inputFileStream, $decryptor, "Read"
    
			[int]$dataLen = $inputFileStream.Length
			[byte[]]$inputFileData = New-Object byte[] $dataLen
			[int]$decryptLength = $decryptStream.Read($inputFileData, 0, $dataLen)
			$decryptStream.Close()
			$inputFileStream.Close()

			$outputFileStream = New-Object System.IO.FileStream($decryptedFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
			$outputFileStream.Write($inputFileData, 0, $decryptLength)
			$outputFileStream.Close()

			$rijndaelCSP.Clear()
			}

			# Decrypt all files except .exe .msi
            $RawFilesLocation = "$using:SourceFiles"
            $RawFiles = Get-ChildItem $RawFilesLocation –Recurse | ? {$_.Attributes -notlike '*Directory*' -and $_.Extension -like '*encrypted'}
            foreach($RawFile in $RawFiles){

            Decrypt–File $RawFile.FullName ($RawFile.FullName -replace "\.encrypted")

            Remove-Item $RawFile.FullName –Force

            }
        }
		GetScript = { # should return a hashtable representing the state of the current node
            if (!(Get-ChildItem "$using:SourceFiles" –Recurse –Filter *.encrypted)) {$result = $True}
			else {$result = $False}
			
			@{
				"DecryptedFiles" = $result
			}
		}
        DependsOn = "[Script]CopyEncryptedSourceFiles"
    }
	# Disable Password Complexity
    Script DisablePasswordComplexity
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            $null = secedit /export /cfg $env:USERPROFILE\secpol.cfg
			$null = (Get-Content $env:USERPROFILE\secpol.cfg) | ? {$_ -match 'PasswordComplexity.=.(.)'}
			$null = Remove-Item –force $env:USERPROFILE\secpol.cfg –confirm:$false
			# make sure PasswordComplexity is set to '0'
			$Matches[1] -eq '0'
        }
        SetScript = {
            # Disable Password Complexity
			secedit /export /cfg $env:USERPROFILE\secpol.cfg
			(gc $env:USERPROFILE\secpol.cfg).replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File $env:USERPROFILE\secpol.cfg
			secedit /configure /db c:\windows\security\local.sdb /cfg $env:USERPROFILE\secpol.cfg /areas SECURITYPOLICY
			Remove-Item –force $env:USERPROFILE\secpol.cfg –confirm:$false
        }
		GetScript = { # should return a hashtable representing the state of the current node
            $null = secedit /export /cfg $env:USERPROFILE\secpol.cfg
			$null = (Get-Content $env:USERPROFILE\secpol.cfg) | ? {$_ -match 'PasswordComplexity.=.(.)'}
			$null = Remove-Item –force $env:USERPROFILE\secpol.cfg –confirm:$false
			
			@{
				"PasswordComplexity" = $Matches[1]
			}
		}
    }
    # Configure VNC Server
	Script ConfigureVNCServer
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            if ((Get-ItemProperty –Path 'HKLM:\Software\RealVNC\vncserver' –ErrorAction SilentlyContinue).Password -eq '0db038a948f57c87f7e4608295c6ea23') {return $True}
			else {return $False}
        }
        SetScript = {
            $process = "$env:ProgramFiles\RealVNC\VNC Server\vnclicense.exe"
			$arguments = "-add $using:VNCKey"
			start-process $process –ArgumentList $arguments –Wait

			New-ItemProperty –Path 'HKLM:\Software\RealVNC\vncserver' –Name 'Authentication' –Value 'VncAuth' –Force
			New-ItemProperty –Path 'HKLM:\Software\RealVNC\vncserver' –Name 'CaptureMethod' –Value '0' –Force
			New-ItemProperty –Path 'HKLM:\Software\RealVNC\vncserver' –Name 'EnableAutoUpdateChecks' –Value '0' –Force
			New-ItemProperty –Path 'HKLM:\Software\RealVNC\vncserver' –Name 'Encryption' –Value 'AlwaysOn' –Force
			New-ItemProperty –Path 'HKLM:\Software\RealVNC\vncserver' –Name 'HttpPort' –Value '5190' –Force
			New-ItemProperty –Path 'HKLM:\Software\RealVNC\vncserver' –Name 'Password' –Value 'facbcf50c3bf1c08' –Force # Passw0rd
			New-ItemProperty –Path 'HKLM:\Software\RealVNC\vncserver' –Name 'RfbPort' –Value '5190' –Force
			New-ItemProperty –Path 'HKLM:\Software\RealVNC\vncserver' –Name 'UserPasswdVerifier' –Value 'VncAuth' –Force

			Restart-Service –Name vncserver –Force
        }
		GetScript = { # should return a hashtable representing the state of the current node
        $result = Test-Path –Path "$env:ProgramFiles\RealVNC\VNC Server\vncserver.exe"
			@{
				"Installed" = $result
			}
		}
		DependsOn = "[Package]InstallVNCServer"
    }

    # Map M Drive & Start Studio Scheduled Task
    Script UserLogonScript
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            if (Get-ScheduledTask –TaskName "UserLogonScript" –ErrorAction SilentlyContinue) {return $True}
			else {return $False}
        }
        SetScript = {
			# M-Drive & StationPlaylist Studio ScheduledTask
            # This will create a scheduled task which will run a UserLogonScript for any user that logs on changing the regional settings for the user to Australia.
            $ShedService = New-Object –comobject 'Schedule.Service'
            $ShedService.Connect()

            $Task = $ShedService.NewTask(0)
            $Task.RegistrationInfo.Description = 'UserLogonScript'
            $Task.Settings.Enabled = $true
            $Task.Settings.AllowDemandStart = $true

            $trigger = $task.triggers.Create(9)
            $trigger.Enabled = $true

            $action = $Task.Actions.Create(0)
            $action.Path = 'PowerShell.exe'
            $action.Arguments = '-ExecutionPolicy Unrestricted -File c:\UserLogonScript.ps1'
            # $action.WorkingDirectory = ''

            $taskFolder = $ShedService.GetFolder("\")
            $taskFolder.RegisterTaskDefinition('UserLogonScript', $Task , 6, 'Users', $null, 4)
        }
		GetScript = { # should return a hashtable representing the state of the current node
            if (Get-ScheduledTask –TaskName "UserLogonScript" –ErrorAction SilentlyContinue) {return $True}
			else {$result = $False}
			@{
				"ScheduledTaskExists" = $result
			}
		}
    }

# Set ACLs for PHP for IIS to process it appropriately
	Script PHPACLs
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            $php_install = "$env:SystemDrive\php"
            $PHPInstallACLs = ((Get-Acl $php_install).Access.IdentityReference)
            $result = $false

            $PHPInstallACLs | % {if($_.Value -eq 'IIS APPPOOL\DefaultAppPool'){$result = $True}}
            return $result
        }
        SetScript = {
            $php_install = "$env:SystemDrive\php"
            
            $acl = get-acl $php_install
            $ar = new-object system.security.accesscontrol.filesystemaccessrule("IIS AppPool\DefaultAppPool", "ReadAndExecute", "ContainerInherit, ObjectInherit", "None","Allow")
            $acl.setaccessrule($ar)
            $ar = new-object system.security.accesscontrol.filesystemaccessrule("Users", "ReadAndExecute", "ContainerInherit, ObjectInherit", "None","Allow")
            $acl.setaccessrule($ar)
            set-acl $php_install $acl

            $php_log = "c:\phplog"

            if ((Test-Path –path $php_log) -ne $True) {
            new-item –type directory –path $php_log}
            $acl = get-acl $php_log
            $ar = new-object system.security.accesscontrol.filesystemaccessrule("Users","Modify","Allow")
            $acl.setaccessrule($ar)
            $ar = new-object system.security.accesscontrol.filesystemaccessrule("IIS AppPool\DefaultAppPool", "Modify", "ContainerInherit, ObjectInherit", "None","Allow")
            $acl.setaccessrule($ar)
            set-acl $php_log $acl
            
            $php_temp = "c:\phptemp"

            if ((Test-Path –path $php_temp) -ne $True) {
            new-item –type directory –path $php_temp}
            $acl = get-acl $php_temp
            $ar = new-object system.security.accesscontrol.filesystemaccessrule("Users","Modify","Allow")
            $acl.setaccessrule($ar)
            $ar = new-object system.security.accesscontrol.filesystemaccessrule("IIS AppPool\DefaultAppPool", "Modify", "ContainerInherit, ObjectInherit", "None","Allow")
            $acl.setaccessrule($ar)
            set-acl $php_temp $acl

        }
		GetScript = { # should return a hashtable representing the state of the current node
            $php_install = "$env:SystemDrive\php"
            $PHPInstallACLs = ((Get-Acl $php_install).Access.IdentityReference)
            $result = $false

            $PHPInstallACLs | % {if($_.Value -eq 'IIS APPPOOL\DefaultAppPool'){$result = $True}}
			@{
				"PHPACLsConfigured" = $result
			}
		}
        DependsOn = "[File]PHPFiles"
    }

# Configure PHP for IIS
	Script ConfigurePHP
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            $result = $true
            if ( (Get-PSSnapin –Name PHPManagerSnapin –ErrorAction SilentlyContinue) -eq $null )
            {
                $result = $false 
            }

            return $result
        }
        SetScript = {
            $php_install = "$env:SystemDrive\php"
            $php_version = '7.0.13'
            $php_log = "$env:SystemDrive\phplog"
            $php_temp = "$env:SystemDrive\phptemp"
            $web_root = "$env:SystemDrive\inetpub\wwwroot"
            $web_log = "$env:SystemDrive\wwwlogs"

            Add-PsSnapin PHPManagerSnapin
            Rename-Item –Path "$php_install\$php_version\php.ini-production" –NewName "$php_install\$php_version\php.ini" –ErrorAction SilentlyContinue
            New-PHPVersion –ScriptProcessor "$php_install\$php_version\php-cgi.exe"
            #Configure Home Office Settings
            Set-PHPSetting –name date.timezone –value "Australia/Sydney"
            Set-PHPSetting –name upload_max_filesize –value "10M"
            Set-PHPSetting –name fastcgi.impersonate –Value '0'
            Set-PHPSetting –name max_execution_time –Value '300'
            #Move logging and temp space to e:
            Set-PHPSetting –name upload_tmp_dir –value $php_temp
            set-phpsetting –name session.save_path –value $php_temp
            Set-PHPSetting –name error_log –value "$php_log\php-errors.log"
            Set-PHPExtension –name php_wincache.dll –status enabled

            if ((Test-Path –path $web_root) -ne $True) {
                new-item –type directory –path $web_root
                $acl = get-acl $web_root
                $ar = new-object system.security.accesscontrol.filesystemaccessrule("Users", "ReadAndExecute", "ContainerInherit, ObjectInherit", "None","Allow")
                $acl.setaccessrule($ar)
                set-acl $web_root $acl
            }

            if ((Test-Path –path $web_log) -ne $True) {
                new-item –type directory –path $web_log
                $acl = get-acl $web_log
                $ar = new-object system.security.accesscontrol.filesystemaccessrule("Users", "ReadAndExecute", "ContainerInherit, ObjectInherit", "None","Allow")
                $acl.setaccessrule($ar)
                set-acl $web_log $acl
            }

        }
		GetScript = { # should return a hashtable representing the state of the current node
            $result = $true
            if ( (Get-PSSnapin –Name PHPManagerSnapin –ErrorAction SilentlyContinue) -eq $null )
            {
                $result = $false 
            }
			@{
				"PHPConfigured" = $result
			}
		}
        DependsOn = "[Script]PHPACLs"
    }

#endregion

################################################################################
##################     Registry Stuff
################################################################################
#region Registry Stuff
	Registry ExecutionPolicy 
	{
        Ensure = 'Present'
        Key = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\'
        ValueName = 'ExecutionPolicy'
        ValueData = 'Unrestricted'
        ValueType = "String"
    }
	# Disable IE First Launch
	Registry DisableFirstRunCustomize 
	{
        Ensure = 'Present'
        Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
        ValueName = 'DisableFirstRunCustomize'
        ValueData = '1'
        ValueType = "String"
    }
    # Disable IE First Launch – Admins
	Registry InternetExplorerEnhancedSecurityConfigurationAdmins1
	{
        Ensure = 'Present'
        Key = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'
        ValueName = 'IsInstalled'
        ValueData = '0'
        ValueType = "DWORD"
    }
    Registry InternetExplorerEnhancedSecurityConfigurationAdmins2
	{
        Ensure = 'Present'
        Key = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
        ValueName = 'IsInstalled'
        ValueData = '0'
        ValueType = "DWORD"
    }
    # Disable IE First Launch – Users
	Registry InternetExplorerEnhancedSecurityConfigurationUsers1
	{
        Ensure = 'Present'
        Key = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
        ValueName = 'IsInstalled'
        ValueData = '0'
        ValueType = "DWORD"
    }
	#endregion

  }

}