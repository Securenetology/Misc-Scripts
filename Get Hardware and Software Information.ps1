#Get Hardware and Software Information
#Author : Dax 
#Version 1.0 | 11/15/2024

#Elevate as Administrator
# Get the ID and security principal of the current user account
 $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
 $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

 # Get the security principal for the Administrator role
 $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

 # Check to see if we are currently running "as Administrator"
 if ($myWindowsPrincipal.IsInRole($adminRole))
    {
    # We are running "as Administrator" - so change the title and background color to indicate this
    $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
    $Host.UI.RawUI.BackgroundColor = "DarkBlue"
    clear-host
    }
 else
    {
    # We are not running "as Administrator" - so relaunch as administrator

    # Create a new process object that starts PowerShell
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";

    # Specify the current script path and name as a parameter
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;

    # Indicate that the process should be elevated
    $newProcess.Verb = "runas";

    # Start the new process
    [System.Diagnostics.Process]::Start($newProcess);

    # Exit from the current, unelevated, process
    exit
    }



function Hardware {
Write-Output -InputObject "`nBIOS"
$Version = @{
	Name       = "Version"
	Expression = {$_.Name}
}
(Get-CimInstance -ClassName CIM_BIOSElement | Select-Object -Property Manufacturer, $Version | Format-Table | Out-String).Trim()

Write-Output -InputObject "`nMotherboard"
(Get-CimInstance -ClassName Win32_BaseBoard | Select-Object -Property Manufacturer, Product | Format-Table | Out-String).Trim()

Write-Output -InputObject "`nSerial number"
(Get-CimInstance -ClassName Win32_BIOS).Serialnumber

Write-Output -InputObject "`nCPU"
$Cores = @{
	Name       = "Cores"
	Expression = {$_.NumberOfCores}
}
$L3CacheSize = @{
	Name       = "L3, MB"
	Expression = {$_.L3CacheSize/1024}
}
$Threads = @{
	Name       = "Threads"
	Expression = {$_.NumberOfLogicalProcessors}
}
(Get-CimInstance -ClassName CIM_Processor | Select-Object -Property Name, $Cores, $L3CacheSize, $Threads | Format-Table | Out-String).Trim()

Write-Output -InputObject "`nRAM"
$Speed = @{
	Name       = "Speed, MHz"
	Expression = {$_.ConfiguredClockSpeed}
}
$Capacity = @{
	Name       = "Capacity, GB"
	Expression = {$_.Capacity/1GB}
}
(Get-CimInstance -ClassName CIM_PhysicalMemory | Select-Object -Property Manufacturer, PartNumber, $Speed, $Capacity | Format-Table | Out-String).Trim()

Write-Output -InputObject "`nPhysical disks"
$Model = @{
	Name       = "Model"
	Expression = {$_.FriendlyName}
}
$MediaType = @{
	Name       = "Drive type"
	Expression = {$_.MediaType}
}
$Size = @{
	Name       = "Size, GB"
	Expression = {[math]::round($_.Size/1GB, 2)}
}
$BusType = @{
	Name       = "Bus type"
	Expression = {$_.BusType}
}
(Get-PhysicalDisk | Select-Object -Property $Model, $MediaType, $BusType, $Size | Format-Table | Out-String).Trim()

# Integrated graphics
if ((Get-CimInstance -ClassName CIM_VideoController | Where-Object -FilterScript {$_.AdapterDACType -eq "Internal"}))
{
	$Caption = @{
		Name       = "Model"
		Expression = {$_.Caption}
	}
	$VRAM = @{
		Name       = "VRAM, MB"
		Expression = {[math]::round($_.AdapterRAM/1MB)}
	}
	Get-CimInstance -ClassName CIM_VideoController | Where-Object -FilterScript {$_.AdapterDACType -eq "Internal"} | Select-Object -Property $Caption, $VRAM
}

# Dedicated graphics
if ((Get-CimInstance -ClassName CIM_VideoController | Where-Object -FilterScript {$_.AdapterDACType -ne "Internal"}))
{
	$qwMemorySize = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -Name HardwareInformation.qwMemorySize -ErrorAction SilentlyContinue)."HardwareInformation.qwMemorySize"
	foreach ($VRAM in $qwMemorySize)
	{
		Get-CimInstance -ClassName CIM_VideoController | Where-Object -FilterScript {$_.AdapterDACType -ne "Internal"} | ForEach-Object -Process {
			[PSCustomObject] @{
				Model      = $_.Caption
				"VRAM, MB" = [math]::round($VRAM/1MB)
			}

			continue
		}
	}
}
}



function Software {
Write-Output User
$PCName = @{
	Name       = "Computer name"
	Expression = {$_.Name}
}
$Domain = @{
	Name       = "Domain"
	Expression = {$_.Domain}
}
$UserName = @{
	Name       = "User Name"
	Expression = {$_.UserName}
}
(Get-CimInstance -ClassName CIM_ComputerSystem | Select-Object -Property $PCName, $Domain, $UserName | Format-Table | Out-String).Trim()

Write-Output "`nLocal Users"
(Get-LocalUser | Out-String).Trim()

Write-Output "`nGroup Membership"
if ((Get-CimInstance -ClassName CIM_ComputerSystem).PartOfDomain -eq $true)
{
	Get-ADPrincipalGroupMembership $env:USERNAME | Select-Object -Property Name
}
#endregion User

#region Operating System
Write-Output "`nOperating System"
$ProductName = @{
	Name = "Product Name"
	Expression = {$_.Caption}
}
$InstallDate = @{
	Name       = "Install Date"
	Expression = {$_.InstallDate.Tostring().Split("")[0]}
}
$Arch = @{
	Name       = "Architecture"
	Expression = {$_.OSArchitecture}
}
$OperatingSystem = Get-CimInstance -ClassName CIM_OperatingSystem | Select-Object -Property $ProductName, $InstallDate, $Arch

$Build = @{
	Name       = "Build"
	Expression = {"$($_.CurrentMajorVersionNumber).$($_.CurrentMinorVersionNumber).$($_.CurrentBuild).$($_.UBR)"}
}
$CurrentVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows nt\CurrentVersion" | Select-Object -Property $Build

([PSCustomObject] @{
	"Product Name" = $OperatingSystem."Product Name"
	"Install Date" = $OperatingSystem."Install Date"
	Build = $CurrentVersion.Build
	Architecture = $OperatingSystem.Architecture
} | Out-String).Trim()
#endregion Operating System

#region Registered apps
Write-Output "`nRegistered apps"
(Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*).DisplayName | Sort-Object
#endregion Registered apps

#region Updates
$HotFixID = @{
$Session = New-Object -ComObject Microsoft.Update.Session
	Name = "KB ID"
	Expression = {$_.HotFixID}
}
$InstalledOn = @{
	Name       = "Installed on"
	Expression = {$_.InstalledOn.Tostring().Split("")[0]}
}
(Get-HotFix | Select-Object -Property $HotFixID, $InstalledOn -Unique | Format-Table | Out-String).Trim()

Write-Output "`nInstalled updates supplied by CBS"
$Session = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$historyCount = $Searcher.GetTotalHistoryCount()

$KB = @{
	Name       = "KB ID"
	Expression = {[regex]::Match($_.Title,"(KB[0-9]{6,7})").Value}
}
$Date = @{
	Name       = "Installed Date"
	Expression = {$_.Date.Tostring().Split("") | Select-Object -Index 0}
}
($Searcher.QueryHistory(0, $historyCount) | Where-Object -FilterScript {
	($_.Title -cmatch "KB") -and ($_.Title -notmatch "Defender") -and ($_.ResultCode -eq 2)
} | Select-Object $KB, $Date | Format-Table | Out-String).Trim()
#endregion Updates

#region Logical drives
Write-Output "`nLogical drives"
$Name = @{
	Name       = "Name"
	Expression = {$_.DeviceID}
}
enum DriveType
{
	RemovableDrive = 2
	HardDrive      = 3
}
$Type = @{
	Name       = "Drive Type"
	Expression = {[System.Enum]::GetName([DriveType],$_.DriveType)}
}
$Size = @{
	Name       = "Size, GB"
	Expression = {[math]::round($_.Size/1GB, 2)}
}
$FreeSpace = @{
	Name       = "FreeSpace, GB"
	Expression = {[math]::round($_.FreeSpace/1GB, 2)}
}
(Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object -FilterScript {$_.DriveType -ne 4} | Select-Object -Property $Name, $Type, $Size, $FreeSpace | Format-Table | Out-String).Trim()
#endregion Logical drives

#region Mapped disks
Write-Output "`nMapped disks"
(Get-SmbMapping | Select-Object -Property LocalPath, RemotePath | Format-Table | Out-String).Trim()
#endregion Mapped disks

#region Printers
Write-Output "`nPrinters"
Get-CimInstance -ClassName CIM_Printer | Select-Object -Property Name, Default, PortName, DriverName, ShareName | Format-Table
#endregion Printers

#region Network
Write-Output "`nDefault IP gateway"
(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration).DefaultIPGateway

Write-Output "`nDNS"
(Get-DnsClientServerAddress -Family IPv4).ServerAddresses
#endregion Network

#region Microsoft Defender threats
Write-Output "`nMicrosoft Defender threats"
enum ThreatStatusID
{
	Unknown          = 0
	Detected         = 1
	Cleaned          = 2
	Quarantined      = 3
	Removed          = 4
	Allowed          = 5
	Blocked          = 6
	QuarantineFailed = 102
	RemoveFailed     = 103
	AllowFailed      = 104
	Abondoned        = 105
	BlockedFailed    = 107
}
(Get-MpThreatDetection | ForEach-Object -Process {
	[PSCustomObject] @{
		"Detected Threats Paths" = $_.Resources
		"ThreatID"             = $_.ThreatID
		"Status"               = [System.Enum]::GetName([ThreatStatusID],$_.ThreatStatusID)
		"Detection Time"       = $_.InitialDetectionTime
	}
} | Sort-Object ThreatID -Unique | Format-Table -AutoSize -Wrap | Out-String).Trim()
#endregion Microsoft Defender threats

#region Microsoft Defender settings
Write-Output "`nMicrosoft Defender settings"
(Get-MpPreference | ForEach-Object -Process {
	[PSCustomObject] @{
		"Excluded IDs"                                  = $_.ThreatIDDefaultAction_Ids | Out-String
		"Excluded Process"                              = $_.ExclusionProcess | Out-String
		"Controlled Folder Access"                      = $_.EnableControlledFolderAccess | Out-String
		"Controlled Folder Access Protected Folders"    = $_.ControlledFolderAccessProtectedFolders | Out-String
		"Controlled Folder Access Allowed Applications" = $_.ControlledFolderAccessAllowedApplications | Out-String
		"Excluded Extensions"                           = $_.ExclusionExtension | Out-String
		"Excluded Paths"                                = $_.ExclusionPath | Out-String
	}
} | Format-List | Out-String).Trim()
#endregion Windows Defender settings
}

Hardware | Out-File -FilePath "$($env:USERPROFILE)\Desktop\Hardware.txt"
Software | Out-File -FilePath "$($env:USERPROFILE)\Desktop\Software.txt"