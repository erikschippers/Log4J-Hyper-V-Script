<#
Author: Erik Schippers
#Look for: Invoke-Command -VMName
#Change the parameters for what to scan, example below
#Options: --all-drives {Scan all drives on Windows} OR USE {--drives c,d}
Version: 0.2
#### Changelog
0.1: initial script
0.2: Changed to only use scanner on guest and process output on Management Server.
#>


$ScannerName = "log4j2-scan.exe"


Write-Host "Give Guest Credential to connect to VM"
$GuestCredential = Get-Credential


$SourcePAth = "C:\Scripts\Log4J\$ScannerName"
$DestPAth = "C:\Temp\Log4J\$ScannerName"
$OutputPath = "C:\temp\Log4J\Output\"
$timestamp = Get-Date -Format "ddMMyyyy-HHMMss"
$ResultFileName = $OutputPath + $timestamp +"-Result.csv"

Import-Module -Name Hyper-V
Start-Transcript -Path C:\Temp\Log4J\Transcript-$timestamp.txt
#Specify VMs to be excluded
$ExcludedVMs = @(
    "VMname"
    
)

$AllVMs = Get-VM | Where {$_.State -eq "Running" -and $_.Name -notin $ExcludedVMS}


if(Test-Path -Path $OutputPath){<#"Path Exists"#>}
else{mkdir $OutputPath}

#Enabling VMIntegrationService if needed
Write-Host "Checking if VMIntegration Services are Enabled, if Not, this will be enabled" -ForegroundColor Magenta
foreach($vm in $AllVMs){
    if((Get-VMIntegrationService -VM $VM -Name "Guest Service Interface").Enabled -eq $false){
        Enable-VMIntegrationService -VMName $VM.Name -Name "Guest Service Interface"
        
        Write-Host "Guest Service Interface Enabled on:" $VM.Name -ForegroundColor Yellow
    }
}
#Wait for Enabling VMIntegrationservices to complete
Start-Sleep -Seconds 60

$Results = @()
#$VM = $AllVMs[1] #For testing purposes
$CounterStatus = 0
foreach($vm in $AllVMs){
    $CounterStatus++
    Write-Host "Starting with VM:"$VM.Name "|" $CounterStatus "of"$AllVMs.count -ForegroundColor Green
   
    Copy-VMFile -VM $VM -SourcePath $SourcePAth -DestinationPath $DestPAth -CreateFullPath -FileSource Host -Force
    #Copy-VMFile -VM $VM -SourcePath $SourcePAth2 -DestinationPath $DestPAth2 -CreateFullPath -FileSource Host -Force
    Start-Sleep -Seconds 2
     $OutputScan = (Invoke-Command -VMName $VM.Name -ScriptBlock {C:\Temp\Log4J\log4j2-scan.exe --all-drives} -Credential $GuestCredential)
     (Invoke-Command -VMName $VM.Name -ScriptBlock {Remove-Item C:\Temp\Log4J -Recurse} -Credential $GuestCredential)
  

    ##########################
    $Scanned = $OutputScan | Where-Object {$_ -like "Scanned*"}
    $FoundVulnerable = $OutputScan | Where-Object {($_ -like "*Vulnerable files") -and ($_ -notlike "*potentially*")}
    $FoundPotentially = $OutputScan | Where-Object {$_ -like "*potentially vulnerable files*"}
    $FoundMitigated = $OutputScan | Where-Object {$_ -like "*mitigated*"}


    $Result = $vm | Select Name
    $Result | Add-Member -Name "Scanned" -MemberType NoteProperty -Value $Scanned -Force
    $Result | Add-Member -Name "Scanned_dirs" -MemberType NoteProperty -Value $Scanned.Split(" ")[1] -Force
    $Result | Add-Member -Name "Scanned_files" -MemberType NoteProperty -Value $Scanned.Split(" ")[4] -Force
    $Result | Add-Member -Name "Found_Number_Vulnerable" -MemberType NoteProperty -Value $FoundVulnerable.Split(" ")[1] -Force
    $Result | Add-Member -Name "Found_Number_Potentially_Vulnerable" -MemberType NoteProperty -Value $FoundPotentially.Split(" ")[1] -Force
    $Result | Add-Member -Name "Found_Number_Mitigated_Vulnerable" -MemberType NoteProperty -Value $FoundMitigated.Split(" ")[1] -Force
    ##########################
    $Results += $Result
    $OutputFileName = $OutputPath+$timestamp+"-"+$vm.Name+".txt"
    $OutputScan > $OutputFileName


}

$Results | Export-Csv -Path $ResultFileName -NoTypeInformation -Delimiter ";"

Stop-Transcript
