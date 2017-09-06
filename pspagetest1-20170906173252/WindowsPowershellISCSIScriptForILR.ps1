Param (
    [string]$VMName,
    [string]$MachineName,
    [string]$OSName,
    [string]$OSVersion,
    [string]$IsServer2008R2,
    [string]$FolderPath,
    [string]$Logfile,
    [string]$TargetPortalAddress,
    [string]$TargetPortalPortNumber,
    [string]$TargetUserName,
    [string]$TargetPassword,
    [string]$InitiatorChapPassword,
    [string]$ScriptId,
    [string]$SequenceNumber
)

Function LogWrite 
{ 
   Param ([string]$logstring) 
   $Timestamp=Get-Date 
   $logdata="[$Timestamp] :" + $logstring 
   Add-content  $Logfile -value $logdata 
} 
Function WaitForExit
{
Echo "`nPress 'Q/q' key to exit ..." 
while($true) 
{     
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") 
    if(($($x.Character) -eq "q") -or ($($x.Character) -eq "Q")) 
    { 
        exit
    } 
}
}
LogWrite $VMName
LogWrite $MachineName
LogWrite $OSName
LogWrite $OSVersion
LogWrite $IsServer2008R2
LogWrite $FolderPath
LogWrite $Logfile
$result=[bool]::TryParse($IsServer2008R2,[ref]$isServer2008R2)
LogWrite $isServer2008R2
LogWrite $TargetPortalAddress
LogWrite $TargetPortalPortNumber
LogWrite $TargetUserName
LogWrite $SequenceNumber
LogWrite $ScriptId

if($TargetPassword -eq "UserInput123456")
{
    Echo "`n"
    $UserEnteredTargetPassword=Read-Host 'Please enter the 15 character password, shown on the portal, to securely connect to the recovery point'
    if($UserEnteredTargetPassword.Length -ne 15)
    {
         Write-Host "You need to enter the complete 15 character password as shown on the portal screen."   -foreground "red"
         Write-Host "You can use the copy button beside the generated password on the portal to copy and paste here."  -foreground "red"
         WaitForExit
    }
}
else
{
    $UserEnteredTargetPassword=$TargetPassword
}

$MyComputerName=(Get-ChildItem -path env:computername).Value
if(($isServer2008R2 -eq $false) -and (($MyComputerName.ToLower() -eq $VMName.ToLower()) -or ($MyComputerName.ToLower() -eq $MachineName.ToLower()))) 
{ 
    LogWrite "Running from Same Machine MyComputerName: $MyComputerName" 
    $StoragePools=Get-StoragePool | Where-Object  FriendlyName -NE "Primordial"
    $StoragePoolCount=$StoragePools.Count
    if($StoragePoolCount -ne 0)
    {
        LogWrite "Has Storage Pools Configured: $StoragePoolCount" 
        Echo "`nPlease find below the Storage space entities present in this machine."
        Echo "`nStorage Pool Friendly Name."
        Echo "-------------------------------"
        Foreach($StorageSpace in $StoragePools)
           {
               Echo "$($StorageSpace.FriendlyName)" 
           }
        Write-Host "`nMount the recovery point only if you are SURE THAT THESE ARE NOT BACKED UP/ PRESENT IN THE RECOVERY POINT." -foreground "red"
        Write-Host "If they are already present, it might corrupt the data irrevocably on this machine." -foreground "red"
        Write-Host "It is recommended to run this script on any other machine with similar OS to recover files." -foreground "red"
        Write-Host "`nShould the recovery point be mounted on this machine? (Y/N) " -foreground "red"
        while($true) 
        {     
            $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") 
            if(($($x.Character) -eq "n") -or ($($x.Character) -eq "N")) 
            { 
                Echo "`nPlease run this script on any other machine with similar OS to recover files."
                WaitForExit
            } 
            elseif(($($x.Character) -eq "y") -or ($($x.Character) -eq "Y")) 
            { 
                break; 
            } 
        }
    }
} 

#Echo "For More details please check log file: $Logfile" 
$LocalPortalAddress ="127.0.0.1" 
$LocalPortalPortNumber =5365 
$MinPort = 5365 
$MaxPort = 5396 
$IsProcessRunning=$false 
$MABILRRegKey="hkcu:\SOFTWARE\Microsoft\Microsoft Azure Backup ILR"
Try 
{ 
    $ProcessId=Get-ItemProperty -Name "ProcessId" -Path "$MABILRRegKey" -ErrorAction Stop 
    $PortNumber=Get-ItemProperty -Name "PortNumber" -Path "$MABILRRegKey" -ErrorAction Stop 
    $LastVMName=Get-ItemProperty -Name "VMName" -Path "$MABILRRegKey" -ErrorAction Stop 
    $LastTargetNodeAddress=Get-ItemProperty -Name "TargetNodeAddress" -Path "$MABILRRegKey" -ErrorAction SilentlyContinue 
    $LastTargetUserName=Get-ItemProperty -Name "TargetUserName" -Path "$MABILRRegKey" -ErrorAction Stop 
    LogWrite "Registry Process Id : $($ProcessId.ProcessId)" 
    LogWrite "Registry PortNumber : $($PortNumber.PortNumber)" 
    if($($LastTargetUserName.TargetUserName) -ne $TargetUserName)
    {
        Echo "`nWe detected a session already connected to a recovery point of the VM $($LastVMName.VMName) ."
        Echo "We need to unmount the volumes before connecting to the new recovery point of VM $VMName,"
        Echo "`nPlease enter 'Y' to proceed or 'N' to abort..." 
        while($true) 
        {     
            $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") 
            if(($($x.Character) -eq "n") -or ($($x.Character) -eq "N")) 
            { 
                Echo "It is recommended to close the earlier session before starting new connection to another RP."
                WaitForExit
            } 
            elseif(($($x.Character) -eq "y") -or ($($x.Character) -eq "Y")) 
            { 
                break; 
            } 
        }
        Echo "`nPlease wait while we disconnect old session..."
        $lastline=""
        $MinPort=($($PortNumber.PortNumber)+1)
        if($MinPort -ge $MaxPort)
        {
            $MinPort=5365
        }
        if($isServer2008R2 -eq $true)
        {
	        LogWrite "Disconnected last target : $($LastTargetNodeAddress.TargetNodeAddress)" 
            $output=ISCSICli.exe SessionList $($LastTargetNodeAddress.TargetNodeAddress)
            LogWrite "Success Status $output." 
            foreach ($outputline in $output)
            {
                if($outputline.Contains($($LastTargetNodeAddress.TargetNodeAddress)))
                {
                    $sessionid=$lastline.Substring(25,33)
                    LogWrite "Disconnecting Session. ID:+.$sessionid" 
                    $output=ISCSICli.exe LogoutTarget $sessionid
                }
                $lastline=$outputline
            }
        }
        else
        {
            Disconnect-IscsiTarget -NodeAddress $($LastTargetNodeAddress.TargetNodeAddress) -ErrorAction SilentlyContinue -Confirm:$false
        }
        
        $Process = Get-Process -Id $($ProcessId.ProcessId) -ErrorAction SilentlyContinue 
        LogWrite "Current Process Name : $($Process.Name)" 
        if( $($Process.Name) -eq "SecureTCPTunnel") 
        { 
            LogWrite "Process is already running on Port $($PortNumber.PortNumber)" 
            Stop-Process -Id $($ProcessId.ProcessId) -ErrorAction SilentlyContinue -Confirm:$false
        }
        $IsProcessRunning=$false 
        if($isServer2008R2 -eq $false)
        {
            Disconnect-IscsiTarget -NodeAddress $($LastTargetNodeAddress.TargetNodeAddress) -ErrorAction SilentlyContinue -Confirm:$false
        }
        Echo "`nOlder session disconnected. Establishing a new session for the new recovery point...."
    }
    else
    { 
        
        $Process = Get-Process -Id $($ProcessId.ProcessId) -ErrorAction SilentlyContinue 
        LogWrite "Current Process Name : $($Process.Name)" 
        LogWrite "Same Script was ran earlier." 
        $MinPort = $($PortNumber.PortNumber) 
        $MaxPort = $($PortNumber.PortNumber) 
        if( $($Process.Name) -eq "SecureTCPTunnel") 
        { 
            LogWrite "Process is already running on Port $($PortNumber.PortNumber)" 
            $IsProcessRunning=$false
            Stop-Process -Id $($ProcessId.ProcessId) -ErrorAction SilentlyContinue -Confirm:$false
        }
    } 
} 
Catch 
{ 
    LogWrite "Process is not running." 
    $IsProcessRunning=$false 
    $PortNumber=$null
    LogWrite "Exception Details: $ErrorMessage, $FailedItem" 
} 
if(!$IsProcessRunning) 
{     
        $ActivationId=Get-Random -Maximum 10000  
        $SecureTCPTunnel = "$FolderPath\SecureTCPTunnel.exe" 
        $SecureTCPTunnelLogfile = $FolderPath + "\SecureTCPTunnelLogFile.log" 

    $Process=Start-Process -FilePath $SecureTCPTunnel -ArgumentList "$MinPort $MaxPort $TargetPortalAddress $TargetPortalPortNumber $TargetUserName $VMName $ActivationId $SecureTCPTunnelLogfile"  -PassThru -WindowStyle Hidden 
    $MaxProcessWaitRetry = 20 
    $CurrentProcessWaitRetryCount = 0 
    while($CurrentProcessWaitRetryCount -lt $MaxProcessWaitRetry) 
    { 
        $ActivationIdReg=Get-ItemProperty -Name "ActivationId" -Path "$MABILRRegKey" -ErrorAction SilentlyContinue
        
        if($($Process.HasExited)) 
        {         
            LogWrite "SecureTCPTunnel is exited with exception." 
            LogWrite "Exit Code: $($Process.ExitCode)" 
            Echo "Failed to create Secure TCP Tunnel for ISCSI. Please retry after sometime." 
            break; 
        } 
        if($($ActivationIdReg.ActivationId) -eq $ActivationId) 
        { 
            LogWrite "Process started and activation id is successfully set." 
            $PortNumber=Get-ItemProperty -Name "PortNumber" -Path "hkcu:\SOFTWARE\Microsoft\Microsoft Azure Backup ILR" -ErrorAction Stop 
            $LocalPortalPortNumber=$($PortNumber.PortNumber) 
            LogWrite "SecureTCPTunnel is listening on Port=$LocalPortalPortNumber" 
            try 
            { 
                # Remove inheritance 
                $acl = Get-Acl $MABILRRegKey
                $acl.SetAccessRuleProtection($true,$true) 
                Set-Acl $MABILRRegKey $acl 
                # Remove ACL 
                $acl = Get-Acl $MABILRRegKey
                $acl.Access | %{$acl.RemoveAccessRule($_)} | Out-Null 
                # Add local admin 
                $permission  = "BUILTIN\Administrators","FullControl", "ContainerInherit,ObjectInherit","None","Allow" 
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule $permission 
                $acl.SetAccessRule($rule) 
                Set-Acl $MABILRRegKey $acl 
            } 
            catch 
            { 
                LogWrite "Exception Details: $ErrorMessage, $FailedItem" 
                LogWrite "Failed to ACL Registry" 
            } 
            break; 
        } 
        $CurrentProcessWaitRetryCount = $CurrentProcessWaitRetryCount + 1 
        Start-Sleep -Milliseconds 100 
    }     
    if($MaxProcessWaitRetry -eq $CurrentProcessWaitRetryCount) 
    { 
        LogWrite "Activation ID is not updated by process. SecureTCPTunnel process failed to connect." 
        Echo "`Unable to access the recovery point. Please make sure that you have enabled access to Azure public IP addresses on the outbound port 3260 and 'https://download.microsoft.com/'"
        WaitForExit
    }         
} 
Try 
{
    Echo "`nConnecting to recovery point using ISCSI service...." 
 
    $job=Start-Job -ScriptBlock {Get-WmiObject -Class Win32_LogicalDisk} 
$dpscript = @" 
list disk 
"@ 
[array]$Temp = $dpscript | diskpart 
ForEach ($Line in $Temp) 
{ 
   If ($Line.StartsWith("  Disk")) 
   { 
           [array]$DisksBefore += $Line 
   } 
} 
    $DiskCountBeforeConnection = $DisksBefore.Count 
} 
Catch 
{ 
    LogWrite "Warning: Failed to get Disk Count from DiskPart." 
} 
$ConnectionSucceeded=$false 
Try 
{ 
    LogWrite "Starting MSiSCSI Service..." 
    Start-Service MSiSCSI 
    LogWrite "MSiSCSI Service Started Successfully." 
    if($isServer2008R2 -eq $true)
    {
	    LogWrite "Discovering Targets from Portal: $TargetPortalAddress, $TargetPortalPortNumber" 
        $output=ISCSICli.exe AddTargetPortal $LocalPortalAddress $LocalPortalPortNumber * * * * * * * * * $TargetUserName $UserEnteredTargetPassword 1
        $success=$output[2]
        Logwrite $output
        LogWrite "Success Status $success." 
        if($success -ne "The operation completed successfully. ")
        {
            throw [System.Exception] $success
        }
        LogWrite "Fetching target list" 
        $output=ISCSICli.exe ListTargets
        $success=$output[$output.Count-1]
        Logwrite $output
        LogWrite "Success Status $success." 
        if($success -ne "The operation completed successfully. ")
        {
            throw [System.Exception] $success
        }
        LogWrite "Total Targets Found : $($output.Count)"
        $UserNameFields=$TargetUserName.Split(';') 
        $UserName=$UserNameFields[2].Split('-') 
        LogWrite "Resource ID: $($UserName[0])"
        foreach($node in $output)
        {
            LogWrite "Target Name: $node"
            if( $node.contains($UserName[0]) -and $node.contains($SequenceNumber))
            {
                 $TargetNodeAddress=$node.trim()
            }
        }
        LogWrite "Fetch Target Succeeded." 
        LogWrite ("Target Found $TargetNodeAddress") 
        LogWrite "Connecting to target $TargetNodeAddress..." 
        $output=ISCSICli.exe QLoginTarget "$TargetNodeAddress" "$TargetUserName" "$UserEnteredTargetPassword"
        if( $($output.count) -gt 3 )
	    {
		    $success=$output[4]
	    }
	    else
	    {
		    $success=$output[2]
	    }
        LogWrite "Success Status $success." 
        if($success -eq "The target has already been logged in via an iSCSI session. ")
        {
            throw [System.Exception] $success
        }
        elseif($success -ne "The operation completed successfully. ")
        {
            throw [System.Exception] $success
        }
     }
        else
	{
	LogWrite "Setting up initiators Chap Secret..." 
        Set-IscsiChapSecret -ChapSecret $InitiatorChapPassword -ErrorAction Stop 
        LogWrite "Your Initiators Chap Secret is : $InitiatorChapPassword" 
        LogWrite "Discovering Targets from Portal: $TargetPortalAddress, $TargetPortalPortNumber" 
        $IscsiTargetPortal=New-IscsiTargetPortal -TargetPortalAddress $LocalPortalAddress -TargetPortalPortNumber $LocalPortalPortNumber -AuthenticationType MUTUALCHAP -ChapUsername $TargetUserName -ChapSecret $UserEnteredTargetPassword -ErrorAction Stop 
        LogWrite "Discovery Succeeded." 
        $TargetNodes=Get-IscsiTarget
        LogWrite "Total Targets Found : $($TargetNodes.Count)"
        $UserNameFields=$TargetUserName.Split(';') 
        $UserName=$UserNameFields[2].Split('-') 
        LogWrite "Resource ID: $($UserName[0])"
        foreach($TargetNode in $TargetNodes)
        {
            LogWrite "Target Name: $($TargetNode.NodeAddress.ToString())"
            if( $TargetNode.NodeAddress.ToString().contains($UserName[0]) -and $TargetNode.NodeAddress.ToString().contains($SequenceNumber))
            {
                 $TargetNodeAddress=$TargetNode.NodeAddress.ToString()
            }
        }
        LogWrite ("Target Found, $TargetNodeAddress")         
        LogWrite "Connecting to target $TargetNodeAddress..." 
        $IscsiConnection=Connect-IscsiTarget -NodeAddress $TargetNodeAddress -TargetPortalAddress $LocalPortalAddress -TargetPortalPortNumber $LocalPortalPortNumber -AuthenticationType MUTUALCHAP -ChapUsername $TargetUserName -ChapSecret $UserEnteredTargetPassword -ErrorAction Stop 
	}
    LogWrite "Connection succeeded!" 
    LogWrite "Operating System will load your Disks and Volumes." 
    LogWrite "Wait few seconds and your volumes will appear in Explorer." 
    Write-Host "`nConnection succeeded!"  -foreground "green"
    Echo "`nPlease wait while we attach volumes of the recovery point." 
    #Echo "Operating System will load your Disks and Volumes." 
    #Echo "Please Wait for few seconds and your volumes will appear in Explorer." 
    Set-ItemProperty  -Name "TargetNodeAddress" -Value "$TargetNodeAddress" -Path "hkcu:\SOFTWARE\Microsoft\Microsoft Azure Backup ILR" -ErrorAction Stop 
    $ConnectionSucceeded=$true 
} 
Catch 
{ 
    $ErrorMessage = $_.Exception.Message 
    $FailedItem = $_.Exception.ItemName 
    if($ErrorMessage -eq "The target has already been logged in via an iSCSI session. ") 
    { 
        Echo "`n$ErrorMessage" 
        $NewVolumesReg=Get-ItemProperty -Name "NewVolumesList" -Path "$MABILRRegKey" -ErrorAction SilentlyContinue
        if($NewVolumesReg)
        {
           $RegVolumesList = $NewVolumesReg.NewVolumesList.Split(';')
           Echo "`n$($RegVolumesList.Count-1) recovery volumes attached"
           Foreach($RegVolume in $RegVolumesList)
           {
               if($RegVolume)
               {
                   Write-Host "`n$RegVolume" -foreground "green"
               }
           }
        }
        Echo "`n*************  Open Explorer to browse for files  *************"
    } 
    elseif($ErrorMessage -eq "Authentication Failure. ")  
    { 
    Write-Host "`nThis script cannot connect to the recovery point. Either the password entered is invalid or the disks have been unmounted. Please enter the correct password or download a new script from the portal."  -foreground "red"
    } 
    else 
    { 
        Write-Host "`nException caught while connecting to Target. Please retry after some time."  -foreground "red"
    } 
    LogWrite "Exception Details: $ErrorMessage, $FailedItem" 
    LogWrite "Exception caught while connecting to Target. Please retry after some time." 
} 
Try 
{ 
if( $ConnectionSucceeded -eq $true ) 
{ 
    Start-Sleep -Seconds 10 
    $MaxRetryCount=12 
    $RetryCount=0 
    LogWrite "Current Disk Count = $DiskCountBeforeConnection" 
    while($RetryCount -le $MaxRetryCount) 
    { 
        remove-variable Temp -ErrorAction SilentlyContinue 
        remove-variable Disks -ErrorAction SilentlyContinue 
        [array]$Temp = $dpscript | diskpart 
        $newDiskFound=$false 
        ForEach ($Line in $Temp) 
        { 
              If ($Line.StartsWith("  Disk")) 
              { 
                $isOld=$false 
                ForEach ($OldLine in $DisksBefore) 
                { 
                    if($Line -eq $OldLine) 
                    { 
                        $isOld=$true 
                    } 
                } 
                if($isOld -eq $false) 
                { 
                    [array]$Disks += $Line 
                    $newDiskFound=$true 
                } 
              }
        } 
        $DiskCountAfterConnection = $Disks.Count 
        LogWrite "New Disk Count = $DiskCountAfterConnection" 
        if($newDiskFound) 
        { 
            LogWrite "New disks are added to System." 
            break;             
        } 
        $RetryCount=$RetryCount+1; 
        Start-Sleep -Seconds 5 
    } 
For ($i=0;$i -le ($Disks.count-1);$i++) 
{ 
 $currLine = $Disks[$i] 
 $currLine -Match "  Disk (?<disknum>...) +(?<sts>.............) +(?<sz>.......) +(?<fr>.......) +(?<dyn>...) +(?<gpt>...)" | Out-Null
 $DiskObj =  New-Object PSObject 
 Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "DiskNumber" -Value $Matches['disknum'].Trim() 
 Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "Status" -Value $Matches['sts'].Trim() 
 Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "Size" -Value $Matches['sz'].Trim() 
 Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "Free" -Value $Matches['fr'].Trim() 
 Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "Dyn" -Value $Matches['dyn'].Trim() 
 Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "Gpt" -Value $Matches['gpt'].Trim() 
    $isDyn=$Matches['dyn'].Trim() 
    LogWrite "Disk:$($DiskObj.DiskNumber), DiskStatus:$($DiskObj.Status) , isDynamic:$isDyn" 
    If (($isDyn -eq "*") -or ($DiskObj.Status -eq "Offline")) 
 { 
$dpscript = @" 
select disk $($DiskObj.DiskNumber) 
detail disk 
"@ 
       [array]$Temp = $dpscript | diskpart 
       ForEach ($Line in $Temp) 
       { 
               If ($Line -cmatch "Disk ID" -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "DiskID" -Value $Line.Split(":")[1].Trim() 
               } 
               ElseIf ($Line.StartsWith("Type") -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "DetailType" -Value $Line.Split(":")[1].Trim() 
               } 
               ElseIf ($Line.StartsWith("Status") -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "DetailStatus" -Value $Line.Split(":")[1].Trim() 
               } 
               ElseIf ($Line.StartsWith("Path") -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "Path" -Value $Line.Split(":")[1].Trim() 
               } 
               ElseIf ($Line.StartsWith("Target") -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "Target" -Value $Line.Split(":")[1].Trim() 
               } 
               ElseIf ($Line.StartsWith("LUN ID") -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "LUNID" -Value $Line.Split(":")[1].Trim() 
               } 
               ElseIf ($Line.StartsWith("Location Path") -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "LocationPath" -Value $Line.Split(":")[1].Trim() 
               } 
               ElseIf ($Line.StartsWith("Current Read-only State") -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "CurrentReadOnlyState" -Value $Line.Split(":")[1].Trim() 
               } 
               ElseIf ($Line.StartsWith("Read-only") -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "ReadOnly" -Value $Line.Split(":")[1].Trim() 
               } 
               ElseIf ($Line.StartsWith("Boot Disk") -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "BootDisk" -Value $Line.Split(":")[1].Trim() 
               } 
               ElseIf ($Line.StartsWith("Pagefile Disk") -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "PagefileDisk" -Value $Line.Split(":")[1].Trim() 
               } 
               ElseIf ($Line.StartsWith("Hibernation File Disk") -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "HibernationFileDisk" -Value $Line.Split(":")[1].Trim() 
               } 
               ElseIf ($Line.StartsWith("Crashdump Disk") -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "CrashdumpDisk" -Value $Line.Split(":")[1].Trim() 
               } 
               ElseIf ($Line.StartsWith("Clustered Disk") -and $Line -match ":") 
               { 
                       Add-Member -InputObject $DiskObj -MemberType NoteProperty -Name "ClusteredDisk" -Value $Line.Split(":")[1].Trim() 
               } 
       } 
} 
   [array]$DiskResults += $DiskObj 
} 
if($isServer2008R2 -eq $true)
{
	$UnhealthyDisksCount=0
}
else
{
	$UnhealthyDisks=Get-PhysicalDisk | Where-Object {($_.OperationalStatus -ne "OK" -or $_.HealthStatus -ne "Healthy") -and $_.Manufacturer -eq "MABILR I"} 
	$UnhealthyDisksCount=$UnhealthyDisks.Count 
}
if($UnhealthyDisksCount -gt 0) 
{ 
LogWrite "Detected Unhealthy Disks in ILR. Total Unhealthy Disk Count =$UnhealthyDisksCount"  
Write-Host "`nWindows detected identical disk/storage pool configuration and prevented import. Please run this script from another machine with similar OS." -foreground "red"
} 
else 
{ 
$dpscript=""; 
ForEach ($Disk in $DiskResults) 
{ 
   If ($Disk.DetailType -eq "iSCSI") 
   { 
        LogWrite "Detected ISCSI Disk. Disk Number= $($Disk.DiskNumber)" 
        if($Disk.Status -eq "Offline") 
        { 
        LogWrite "Disk is in Offline State. Disk Number= $($Disk.DiskNumber) " 
$dpscript += @" 
"" 
select disk $($Disk.DiskNumber) 
online disk  
"@ 
        } 
           If ($Disk.DetailStatus -eq "Foreign") 
       { 
        LogWrite "Detected Dynamic disk. Disk Number= $($Disk.DiskNumber)" 
           [array]$iSCSIForeignDisks += $Disk 
$dpscript += @" 
"" 
select disk $($Disk.DiskNumber) 
import NoErr 
"@ 
           } 
   } 
} 
LogWrite $DiskResults 
LogWrite $dpscript 
$Temp = $dpscript | diskpart 
LogWrite $Temp 
Start-Sleep -Seconds 5 
$MaxJobRetryCount=300 
$CurrentJobRetryCount=0 
while($CurrentJobRetryCount -lt $MaxJobRetryCount) 
{ 
    $jobstate=$job.JobStateInfo.State
    LogWrite "Status $jobstate" 
    if(($job.JobStateInfo.State -ne "Running") -and ($job.JobStateInfo.State -ne "NotStarted")) 
    { 
       break;  
    } 
    $CurrentJobRetryCount=$CurrentJobRetryCount+1 
    Start-Sleep -Milliseconds 1000 
} 
if($job.JobStateInfo.State -ne "Completed") 
{ 
    LogWrite "Failed to fetch Volume List. Status $($job.State) , Error : $($job.Error)"    
} 
else 
{ 
    $VolumesBeforeConnection=Receive-Job -Job $job 
    $job=Start-Job -ScriptBlock {Get-WmiObject -Class Win32_LogicalDisk} 
    $CurrentJobRetryCount=0 
    while($CurrentJobRetryCount -lt $MaxJobRetryCount) 
    { 
	$jobstate=$job.JobStateInfo.State
	LogWrite "Status $jobstate" 
        if(($job.JobStateInfo.State -ne "Running") -and ($job.JobStateInfo.State -ne "NotStarted")) 
        { 
           break;  
        } 
        $CurrentJobRetryCount=$CurrentJobRetryCount+1 
        Start-Sleep -Milliseconds 1000 
    } 
    if($job.JobStateInfo.State -ne "Completed") 
    { 
        LogWrite "Failed to fetch Volume List. Status $($job.State) , Error : $($job.Error)"    
    } 
    else 
    { 
        $VolumesAfterConnection=Receive-Job -Job $job 
        $NewVolumes="" 
        ForEach($Volume in $VolumesAfterConnection) 
        { 
            $isnew=$true 
            ForEach($VolumeOld in $VolumesBeforeConnection) 
            { 
                if($($Volume.Name) -eq $($VolumeOld.Name)) 
                { 
                    $isnew=$false 
                } 
            } 
            if($isnew) 
            { 
                if($($Volume.VolumeName))
                {
                   $VolumeLabel=$($Volume.VolumeName)
                }
                else
                {
                   $VolumeLabel="Local Disk"                   
                }
                [array]$NewVolumesList += "$($Volume.Name)\$VolumeLabel" 
                $NewVolumesString += "$($Volume.Name)\$VolumeLabel;" 
            } 
        }
        Echo "`n$($NewVolumesList.Count) recovery volumes attached"
        ForEach($VolumeName in $NewVolumesList) 
        {
            Write-Host "`n$VolumeName"  -foreground "green"
        }
        Set-ItemProperty -Name "NewVolumesList" -Path "$MABILRRegKey" -Value "$NewVolumesString" -ErrorAction SilentlyContinue
    } 
} 
Echo "`n*************  Open Explorer to browse for files  *************" 
Echo "`nAfter recovery, to remove the disks and close the connection to the recovery point, please click 'Unmount Disks' in step 3 of the portal."
} 
} 
} 
Catch 
{ 
$ErrorMessage = $_.Exception.Message 
$FailedItem = $_.Exception.ItemName 
LogWrite "Exception Details: $ErrorMessage, $FailedItem" 
LogWrite "Exception caught while importing Dynamic Disks. Please retry after some time." 
Write-Host "Exception caught while loading the Disks. Please retry after some time."  -foreground "red"
} 
WaitForExit