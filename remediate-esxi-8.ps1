<#
    Script Name: VMware vSphere ESXi Host Security Settings Remediation Utility
    Copyright (C) 2024 Broadcom, Inc. All rights reserved.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
#>

<#
    This software is provided as is and any express or implied warranties,
    including, but not limited to, the implied warranties of merchantability and
    fitness for a particular purpose are disclaimed. In no event shall the
    copyright holder or contributors be liable for any direct, indirect,
    incidental, special, exemplary, or consequential damages (including, but not
    limited to, procurement of substitute goods or services; loss of use, data,
    or profits; or business interruption) however caused and on any theory of
    liability, whether in contract, strict liability, or tort (including
    negligence or otherwise) arising in any way out of the use of this software,
    even if advised of the possibility of such damage. The provider makes no
    claims, promises, or guarantees about the accuracy, completeness, or adequacy
    of this sample. Organizations should engage appropriate legal, business,
    technical, and audit expertise within their specific organization for review
    of requirements and effectiveness of implementations. You acknowledge that
    there may be performance or other considerations, and that this example may
    make assumptions which may not be valid in your environment or organization.
    This software is not supported by anyone.

    Make backups of all configurations and data before using this tool. Where
    prompted, monitor task progress directly in the vSphere Client.
#>

Param (
    # ESXi Host Name
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Name,
    # Output File Name
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFileName,
    # Accept-EULA
    [Parameter(Mandatory = $false)]
    [switch]$AcceptEULA,
    # Skip safety checks
    [Parameter(Mandatory = $false)]
    [switch]$NoSafetyChecks,
    # Remediate standard virtual network switches
    [Parameter(Mandatory = $false)]
    [switch]$RemediateStandardSwitches = $false,
    # Enable lockdown mode
    [Parameter(Mandatory = $false)]
    [switch]$EnableLockdownMode = $false,
    # Remediate TLS ciphers
    [Parameter(Mandatory = $false)]
    [switch]$RemediateTLSCiphers = $false
)

#####################
# Log to both screen and file
function Log-Message {
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Message = "",

        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "EULA", "PASS", "FAIL", "UPDATE")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Output to screen
    switch ($Level) {
        "INFO" { Write-Host $logEntry -ForegroundColor White }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "EULA" { Write-Host $logEntry -ForegroundColor Cyan }
        "PASS" { Write-Host $logEntry -ForegroundColor Gray }
        "FAIL" { Write-Host $logEntry -ForegroundColor Yellow }
        "UPDATE" { Write-Host $logEntry -ForegroundColor Green }
    }
    
    # Append to file
    if ($OutputFileName) {
        $logEntry | Out-File -FilePath $OutputFileName -Append
    }
}

#####################
# Accept EULA and terms to continue
Function Accept-EULA() {
    Log-Message "This software is provided as is and any express or implied warranties, including," -Level "EULA"
    Log-Message "but not limited to, the implied warranties of merchantability and fitness for a particular" -Level "EULA"
    Log-Message "purpose are disclaimed. In no event shall the copyright holder or contributors be liable" -Level "EULA"
    Log-Message "for any direct, indirect, incidental, special, exemplary, or consequential damages (including," -Level "EULA"
    Log-Message "but not limited to, procurement of substitute goods or services; loss of use, data, or" -Level "EULA"
    Log-Message "profits; or business interruption) however caused and on any theory of liability, whether" -Level "EULA"
    Log-Message "in contract, strict liability, or tort (including negligence or otherwise) arising in any" -Level "EULA"
    Log-Message "way out of the use of this software, even if advised of the possibility of such damage." -Level "EULA"
    Log-Message "The provider makes no claims, promises, or guarantees about the accuracy, completeness, or" -Level "EULA"
    Log-Message "adequacy of this sample. Organizations should engage appropriate legal, business, technical," -Level "EULA"
    Log-Message "and audit expertise within their specific organization for review of requirements and" -Level "EULA"
    Log-Message "effectiveness of implementations. You acknowledge that there may be performance or other" -Level "EULA"
    Log-Message "considerations, and that this example may make assumptions which may not be valid in your" -Level "EULA"
    Log-Message "environment or organization." -Level "EULA"
    Log-Message "" -Level "EULA"
    Log-Message "Type 'yes' to accept all terms and risk. Type 'no' to exit." -Level "EULA"

    $response = Read-Host "Do you accept the EULA? (yes/no)"
    if ($response -ne "yes") {
        Log-Message "EULA not accepted. Exiting script." -Level "ERROR"
        Exit
    }
}

Function Do-Pause() {
    Log-Message "Check the vSphere Client to make sure all tasks have completed, then press Enter to continue." -Level "INFO"
    Read-Host "Press Enter to continue"
}

#####################
# Check to see if we have the required version of VMware.PowerCLI
Function Check-PowerCLI() {
    $installedVersion = (Get-InstalledModule -Name 'VMware.PowerCLI' -AllVersions -ErrorAction SilentlyContinue).Version | Sort-Object -Desc | Select-Object -First 1
    if ('13.3.0' -gt $installedVersion) {
        Log-Message "This script requires PowerCLI 13.3 or newer. Current version is $installedVersion" -Level "ERROR"
        Log-Message "Instructions for installation & upgrade can be found at https://developer.vmware.com/powercli" -Level "ERROR"
        Log-Message "Some installations of PowerCLI cannot be detected. Use -NoSafetyChecks if you are sure." -Level "ERROR"
        Exit
    }
}

#####################
# Check to see if we are connected to the ESXi host
Function Check-ESXiConnection() {
    if ($null -eq (Get-VIServer -Server $Name -ErrorAction SilentlyContinue)) {
        Log-Message "Connecting to ESXi host $Name..." -Level "INFO"
        try {
            Connect-VIServer -Server $Name -ErrorAction Stop
            Log-Message "Successfully connected to ESXi host $Name." -Level "INFO"
        }
        catch {
            Log-Message "Failed to connect to ESXi host $Name. Error: $_" -Level "ERROR"
            Exit
        }
    }
    else {
        Log-Message "Already connected to ESXi host $Name." -Level "INFO"
    }
}

#####################
# Check to see if we are attached to supported hosts. Older hosts might work but things change.
Function Check-Hosts() {
    $ESXi = Get-VMHost
    foreach ($hostVersion in $ESXi.Version) {
        Log-Message "Skipping version validation for host version $hostVersion." -Level "INFO"
    }
}

#######################################################################################################

$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Log-Message "VMware ESXi Host Security Settings Remediation Utility 803-20240625-01" -Level "INFO"
Log-Message "Remediation of $name started at $currentDateTime from $env:COMPUTERNAME by $env:USERNAME" -Level "INFO"

# Accept EULA and terms to continue
if ($false -eq $AcceptEULA) {
    Accept-EULA
    Log-Message "EULA accepted." -Level "INFO"
}
else {
    Log-Message "EULA accepted." -Level "INFO"
}

# Safety checks
if ($false -eq $NoSafetyChecks) {
    #Check-PowerCLI
    Check-ESXiConnection
    Check-Hosts
}
else {
    Log-Message "Safety checks skipped." -Level "INFO"
}

#####################
# By removing or commenting this section you accept any and all risk of running this script.
#
# This kit is intended to provide general guidance for organizations that are considering Broadcom solutions. The information contained
# in this document is for educational and informational purposes only. This document is not intended to provide advice and is provided “AS IS.”
# Broadcom makes no claims, promises, or guarantees about the accuracy, completeness, or adequacy of the information contained herein.
# Organizations should engage appropriate legal, business, technical, and audit expertise within their specific organization for 
# review of requirements and effectiveness of implementations.
#
# You acknowledge that Broadcom is not responsible for the results of any actions taken by you or your organization
# based on the information provided in this kit, or through the execution of this script.
#
# Do not run this script in a production environment. It will change virtual switch settings, port groups, and numerous other settings
# that may cause operational issues. It may also set things that require host reboots.
#
# See the included documentation for more information.
#
# Log-Message "This script should not be used in a production environment." -Level "ERROR"
# Log-Message "It will change things that can cause operational issues." -Level "ERROR"
# Log-Message "It may also set things that require host reboots." -Level "ERROR"
# Log-Message "If you accept the risk, please remove or comment this section of the" -Level "ERROR"
# Log-Message "script (lines 209-232). By doing so, you accept any and all risk this" -Level "ERROR"
# Log-Message "script and these commands may pose to your environment." -Level "ERROR"
# Exit

#####################
# Read the ESXi host into objects and views once to save time & resources
$obj = Get-VMHost $name -ErrorAction Stop
$view = Get-View -VIObject $obj
$ESXcli = Get-EsxCli -VMHost $obj -V2

#####################
# Tests for advanced parameters
$scg_adv = @{
    
    # 'Security.AccountUnlockTime'                     = 900
    # 'Security.AccountLockFailures'                   = 5
    'Security.PasswordQualityControl'           = 'similar=deny retry=3 min=disabled,disabled,disabled,disabled,15 max=64'
    # 'Security.PasswordHistory'                       = 5
    'Security.PasswordMaxDays'                  = 9999
    # 'Config.HostAgent.vmacore.soap.sessionTimeout'   = 30
    # 'Config.HostAgent.plugins.solo.enableMob'        = $false
    # 'UserVars.DcuiTimeOut'                           = 600
    # 'UserVars.SuppressHyperthreadWarning'            = 0
    'UserVars.SuppressShellWarning'             = 0
    # 'UserVars.HostClientSessionTimeout'              = 900
    # 'Net.BMCNetworkEnable'                           = 0
    'DCUI.Access'                               = 'root'
    'Syslog.global.auditRecord.storageEnable'   = $true
    'Syslog.global.auditRecord.storageCapacity' = 100
    'Syslog.global.auditRecord.remoteEnable'    = $true
    # 'Config.HostAgent.log.level'                     = 'info'
    'Syslog.global.logLevel'                    = 'info'
    # 'Syslog.global.certificate.checkSSLCerts'        = $true
    # 'Syslog.global.certificate.strictX509Compliance' = $true
    # 'Net.BlockGuestBPDU'                             = 1
    # 'Net.DVFilterBindIpAddress'                      = ''
    'UserVars.ESXiShellInteractiveTimeOut'      = 900
    'UserVars.ESXiShellTimeOut'                 = 600
    # 'UserVars.ESXiVPsDisabledProtocols'              = "sslv3,tlsv1,tlsv1.1"
    # 'Mem.ShareForceSalting'                          = 2
    # 'VMkernel.Boot.execInstalledOnly'                = $true
    'Mem.MemEagerZero'                          = 1

}

foreach ($param in $scg_adv.GetEnumerator() ) {
    $vmval = (Get-AdvancedSetting -Entity $obj "$($param.Name)").Value

    if ($vmval -eq $($param.Value)) {
        Log-Message "$name`: $($param.Name) configured correctly ($vmval)" -Level "PASS"
    }
    else {
        try {
            Get-AdvancedSetting -Entity $obj "$($param.Name)" | Set-AdvancedSetting -Value $($param.Value) -Confirm:$false -ErrorAction Stop | Out-Null
            Log-Message "$name`: $($param.Name) has been updated ($vmval -> $($param.Value))" -Level "UPDATE"
        }
        catch {
            Log-Message "$name`: $($param.Name) could not be updated ($vmval)" -Level "FAIL"
        }
    }
}

#####################
# Tests for banners
$scg_banner = @{

    'Annotations.WelcomeMessage' = ''
    'Config.Etc.issue'           = ''

}

$sample_banner = "****************************************************************************`n* Authorized users only. Actual or attempted unauthorized use of this      *`n* system is prohibited and may result in criminal, civil, security, or     *`n* administrative proceedings and/or penalties. Use of this information     *`n* system indicates consent to monitoring and recording, without notice     *`n* or permission. Users have no expectation of privacy. Any information     *`n* stored on or transiting this system, or obtained by monitoring and/or    *`n* recording, may be disclosed to law enforcement and/or used in accordance *`n* with Federal law, State statute, and organization policy. If you are not *`n* an authorized user of this system, exit the system at this time.         *`n****************************************************************************`n"

foreach ($param in $scg_banner.GetEnumerator() ) {
    $vmval = (Get-AdvancedSetting -Entity $obj "$($param.Name)").Value

    if ($vmval -eq $($param.Value)) {
        try {
            Get-AdvancedSetting -Entity $obj "$($param.Name)" | Set-AdvancedSetting -Value $sample_banner -Confirm:$false -ErrorAction Stop | Out-Null
            Log-Message "$name`: $($param.Name) has been updated ($vmval -> $sample_banner)" -Level "UPDATE"
        }
        catch {
            Log-Message "$name`: $($param.Name) could not be updated ($vmval)" -Level "FAIL"
        }
    }
    else {
        Log-Message "$name`: $($param.Name) configured correctly ($vmval)" -Level "PASS"
    }
}

#####################
# Test DCUI user
$value = $ESXcli.system.account.list.Invoke() | Where-Object { $_.UserID -eq 'dcui' } | Select-Object -ExpandProperty Shellaccess
if ($value -eq 'false') {
    Log-Message "$name`: DCUI user has shell access deactivated ($value)" -Level "PASS"
}
else {
    try {
        $arguments = $ESXcli.system.account.set.CreateArgs()
        $arguments.id = 'dcui'
        $arguments.shellaccess = "false"
        $ESXcli.system.account.set.Invoke($arguments) | Out-Null
        $success = $true
    }
    catch {
        Log-Message "$name`: DCUI user could not be updated ($value)" -Level "FAIL"
    }
    
    if ($success) {
        Log-Message "$name`: DCUI user has been updated ($value -> false)" -Level "UPDATE"
        $success = $false
    }
}


#####################
# Test NTP configurations (service enablement is tested later)
$value = $obj | Get-VMHostNtpServer
if ($null -eq $value) {
    try {
        $ntp0 = "10.128.231.229"


        $obj | Add-VMHostNTPServer -NtpServer $ntp0 , $ntp1 , $ntp2 , $ntp3 -Confirm:$false | Out-Null
        $success = $true
    }
    catch {
        Log-Message "$name`: NTP client could not be configured ($value)" -Level "FAIL"
    }
    
    if ($success) {
        Log-Message "$name`: NTP client has been configured with sample values (0.pool.ntp.org, 1.pool.ntp.org, 2.pool.ntp.org, 3.pool.ntp.org)" -Level "UPDATE"
        $success = $false
    }
}
else {
    Log-Message "$name`: NTP client already configured ($value)" -Level "PASS"
}

#####################
# Test ESXi services
$services_should_be_false = "sfcbd-watchdog", "TSM", "slpd", "snmpd", "TSM-SSH"

foreach ($service in $services_should_be_false) {
    $value = $obj | Get-VMHostService | Where-Object { $_.Key -eq $service } | Select-Object -ExpandProperty Running
    if ($value -eq $false) {
        Log-Message "$name`: $service is not running ($value)" -Level "PASS"
    }
    else {
        try {
            $obj | Get-VMHostService | Where-Object { $_.Key -eq $service } | Stop-VMHostService -Confirm:$false | Out-Null
            $success = $true
        }
        catch {
            Log-Message "$name`: $service could not be stopped ($value)" -Level "FAIL"
        }
        
        if ($success) {
            Log-Message "$name`: $service has been stopped ($value -> false)" -Level "UPDATE"
            $success = $false
        }
    }

    $value = $obj | Get-VMHostService | Where-Object { $_.Key -eq $service } | Select-Object -ExpandProperty Policy
    if ($value -eq 'off') {
        Log-Message "$name`: $service is not configured to start ($value)" -Level "PASS"
    }
    else {
        try {
            $obj | Get-VMHostService | Where-Object { $_.Key -eq $service } | Set-VMHostService -Policy "off" -Confirm:$false | Out-Null
            $success = $true
        }
        catch {
            Log-Message "$name`: $service could not be configured ($value)" -Level "FAIL"
        }
        
        if ($success) {
            Log-Message "$name`: $service has been configured ($value -> off)" -Level "UPDATE"
            $success = $false
        }
    }
}

#####################
# Enable lockdown mode, if requested
if ($EnableLockdownMode) {
    $value = ((Get-View($view).ConfigManager.HostAccessManager)).QueryLockdownExceptions()
    if ([string]::IsNullOrEmpty($value)) {
        Log-Message "$name`: Lockdown Mode exception users configured correctly ($value)" -Level "PASS"
    }
    else {
        try {
            ((Get-View($view).ConfigManager.HostAccessManager)).UpdateLockdownExceptions($NULL)
            $success = $true
        }
        catch {
            Log-Message "$name`: Lockdown Mode exception users could not be configured ($value)" -Level "FAIL"
        }
        
        if ($success) {
            Log-Message "$name`: Lockdown Mode exception users have been configured ($value -> NULL)" -Level "UPDATE"
            $success = $false
        }
    }
    
    $value = (Get-View ($view).ConfigManager.HostAccessManager).LockdownMode
    if ($value -eq 'lockdownDisabled') {
        try {
            ((Get-View($view).ConfigManager.HostAccessManager)).ChangeLockdownMode('lockdownNormal')
            $success = $true
        }
        catch {
            Log-Message "$name`: Lockdown Mode could not be configured ($value)" -Level "FAIL"
        }
        
        if ($success) {
            Log-Message "$name`: Lockdown Mode has been configured ($value -> lockdownNormal)" -Level "UPDATE"
            $success = $false
        }
    }
    else {
        Log-Message "$name`: Lockdown Mode is configured correctly ($value)" -Level "PASS"
    }
}

#####################
# Test TLS profile
if ($RemediateTLSCiphers) {
    $value = $ESXcli.system.tls.server.get.invoke() | Select-Object -ExpandProperty Profile
    if ($value -eq 'NIST_2024') {
        Log-Message "$name`: TLS profile is configured correctly ($value)" -Level "PASS"
    }
    else {
        try {
            $arguments = $ESXcli.system.tls.server.set.CreateArgs()
            $arguments.profile = "NIST_2024"
            $ESXcli.system.tls.server.set.invoke($arguments) | Out-Null
            $success = $true
        }
        catch {
            Log-Message "$name`: TLS profile could not be updated ($value)" -Level "FAIL"
        }
        
        if ($success) {
            Log-Message "$name`: TLS profile has been updated ($value -> NIST_2024)" -Level "UPDATE"
            $success = $false
        }
    }
}

Log-Message "Remediation of $name completed at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" -Level "INFO"
Log-Message "Re-run the corresponding audit script to verify the remediation." -Level "INFO"
Log-Message "Remember to address security controls that are not covered by these tools." -Level "INFO"