<#
.SYNOPSIS
Removes user profiles on computers running Windows Vista or later.

.DESCRIPTION
Removes specified user profiles found on a computer (local or remote) running Windows Vista or later, 
and logs the information in a CSV file.  If no computer names are provided, the script will remove the profiles 
of the machine where it is running.  You can provide user names to be skipped on the command line, or via
an input file.

.PARAMETER computerNames
The name, or names of computers whose profiles are to be removed.  If providing more than one name,
list them separated by commas.

.PARAMETER excludedUsers

The name or names of the user accounts that should NOT be removed.

.PARAMETER excludedUsersInputFile

A file containing the name or names of the user accounts that should NOT be removed.  The file should
contain one user account per line.

.PARAMETER logFile
The log file that will be written with details of profile removal.  By default, the 
file is written to the same directory where the script resides, and has the .csv extension.

.PARAMETER whatIf

If specified, the script will simulate profile removal but won't actually remove anything.

.PARAMETER confirm

If specified, the script will prompt for confirmation for every profile it intends to remove.

.EXAMPLE
.\Remove-UserProfiles.ps1 -whatIf

.EXAMPLE
.\Remove-UserProfiles.ps1 -computerNames COMPUTER1 -confirm:$false

.EXAMPLE
.\Remove-UserProfiles.ps1 -computerNames COMPUTER1,COMPUTER1,COMPUTER1

.EXAMPLE
.\Remove-UserProfiles.ps1 -computerNames COMPUTER1,COMPUTER1,COMPUTER1 -excludedUsers domain\user1,domain\user2

.EXAMPLE
.\Remove-UserProfiles.ps1 -computerNames COMPUTER1,COMPUTER1,COMPUTER1 -excludedUsersInputFile c:\userlist.txt

.EXAMPLE
.\Remove-UserProfiles.ps1 -computerNames COMPUTER1,COMPUTER1,COMPUTER1 -logFile c:\logfile.txt
#>
[CmdletBinding(DefaultParametersetName="ExcludedUsersFromCommandLine")]
param(
    [Parameter(Position=0,ValueFromPipeline=$true)]
    $computerNames,
    [Parameter(ParameterSetName="ExcludedUsersFromCommandLine")]
    $excludedUsers,
    [Parameter(ParameterSetName="ExcludedUsersFromFile")]
    $excludedUsersInputFile,
    [switch]
    $whatIf,
    [switch]
    $confirm=$true,
    [ValidateNotNullOrEmpty()]
    [string]
    $logFile="removeprofileslog.csv"
)

Function Log-Message {
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $userProfile,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $removalStatus
    )

    $currentDate = Get-Date
    $dateString = $currentDate.toShortDateString()
    $timeString = $currentDate.toShortTimeString()
    
    Add-Content $LogFile ($dateString + " " + `
                            $timeString + "," + `
                            $userProfile.computerName + "," + `
                            $userProfile.accountName + "," + `
                            $userProfile.SID + "," + `
                            $userProfile.LocalPath + "," + `
                            $(Convert-WMIDateStringToDate -dateString $userProfile.LastUseTime) + "," + `
                            $removalStatus)
}

Function Convert-WMIDateStringToDate {
    param (
        [parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]
        $dateString
    )

    if ($dateString) {
        return [System.Management.ManagementDateTimeConverter]::ToDateTime($dateString)
    }
}

Function Get-UserProfiles {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $computerName
    )

    return Get-WmiObject -class Win32_UserProfile -computername $computerName
}

Function Get-AdUserForSid {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $sid
    )

    try {
        $userSid = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $user = $userSid.Translate([System.Security.Principal.NTAccount])
        return $user.Value
    } catch [System.Security.Principal.IdentityNotMappedException] {
        return $null
    }
}

Function Get-LocalUserForSid {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $sid,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $computerName
    )

    try {
        $user = Get-WmiObject win32_useraccount -Filter "SID='$sid' AND domain='$computerName'" -computername $computerName
        return $user.Name
    } catch {
        return $null
    }
}

Function Update-ProfileWithAccountName {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $userProfile,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $computerName
    )
  
    $accountName = Get-AdUserForSid -sid $userProfile.SID
    if(!$accountName) {
        $accountName = Get-LocalUserForSid -sid $userProfile.SID -computerName $computerName
    }
 
    Add-Member -InputObject $userProfile -MemberType NoteProperty -Value $accountName -Name "accountName"
    Add-Member -InputObject $userProfile -MemberType NoteProperty -Value $computerName -Name "computerName"
    return $userProfile
}

Function Should-AccountBeSpared {
    param(
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyString()]
        $userProfile,
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [array]
        $accountNamesToBeSpared
    )

    if ($userProfile.accountName -ne $null) {
        foreach ($name in $accountNamesToBeSpared) {
            if (([string]::Compare($userProfile.accountName, $name, $true)) -eq 0) {
                return $true
            }
        }
    }
    return $false
}

Function Write-ProfileDetails {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $userProfile
    )

    Write-Host "Computer:`t" $userProfile.computerName
    Write-Host "SID:`t`t" $userProfile.SID
    Write-Host "Account:`t" $userProfile.accountName
    Write-Host "Local Path:`t" $userProfile.LocalPath
    Write-Host "Last Use:`t" $(Convert-WMIDateStringToDate -dateString $userProfile.LastUseTime)
}

Function Prompt-ForConfirmation {
    Write-Host "`nAre you sure you want to remove profile?"
    $answer = Read-Host "[Y] Yes, [N] No, [A] All: "
    return $answer.toLower()
}



if ($computerNames -eq $null) {
    $computerNames = Hostname
}

if ($confirm -eq $false) {
    $answer = "a"
}

if ($excludedUsersInputFile) {
    $excludedUsers = Get-Content $excludedUsersInputFile
}

foreach ($computerName in $computerNames) {
    $allUserProfiles = Get-UserProfiles -computerName $computerName
    
    foreach ($userProfile in $allUserProfiles) {
        $removalStatus = ""
        $userProfile = Update-ProfileWithAccountName -userProfile $userProfile -computerName $computerName

        if ($userProfile.Special -ne $true) {
            Write-ProfileDetails $userProfile

            if ((Should-AccountBeSpared -userProfile $userProfile -accountNamesToBeSpared $excludedUsers) -eq $true) {
                $removalStatus = "Skipped: Account is in the exclusion list."
            } else {
                if ($userProfile.Loaded -eq $true) {
                    $removalStatus = "Skipped: Profile in use."
                } else {
                    if ($confirm) {
                        $answer = Prompt-ForConfirmation
                        
                        if ($answer.compareTo("a") -eq 0) {
                            $confirm = $false
                        }
                    }

                    if (($answer.compareTo("y") -eq 0) -or ($answer.compareTo("a") -eq 0))  {
                        $removalStatus = "Removed"
                        if ($whatIf -ne $true) {
                            $userProfile.Delete()
                        }
                    } else {
                       $removalStatus = "Skipped"
                    }
                }
            }

            if ($whatIf) {
                $removalStatus = "What If - " + $removalStatus
            }
            Write-Host $removalStatus -Foreground Yellow
            Log-Message $userProfile $removalStatus
        }
    }
}