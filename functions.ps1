###########################################################################
# __________                           _________.__           .__  .__    #
# \______   \______  _  __ ___________/   _____/|  |__   ____ |  | |  |   #
#  |     ___/  _ \ \/ \/ // __ \_  __ \_____  \ |  |  \_/ __ \|  | |  |   #
#  |    |  (  <_> )     /\  ___/|  | \/        \|   Y  \  ___/|  |_|  |__ #
#  |____|   \____/ \/\_/  \___  >__| /_______  /|___|  /\___  >____/____/ #
#                             \/             \/      \/     \/            # 
#       ____________________________________________________________      #
#      | functions.ps1 - PowerShell functions for AD administrators |     #
#       ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯      #
###########################################################################

# CHANGE LOG ##############################################################
#
# 22/9/2016 - Nick James <omniomi>
#     - File created
#     - [Added] Get-LoggedOn, Get-ServiceUsers, Get-RDPUsers, Get-LocalGroupMembers, Get-Administrators
# 
# 23/9/2016 - Nick James <omniomi>
#     - [Added] Copy-GroupToGroup
#     - [Added] Documentation
#     - [Expanded] Get-Help documentation
#     - [Fixed] Parameter syntax for Get-* functions
#
# 26/9/2016 - Nick James <omniomi>
#     - [Added] Get-TaskUsers
#     - [Changed] All -ShowNegative to -SupressNegative, this reverses behaviour. 
#     - [Added] -ShowErrors to all Get cmdlets to display errors.
#
# 28/9/2016 - Nick James <omniomi>
#     - [Added] Do-LockoutAudit
#
    
# NOTES ###################################################################
#
# * All cmdlets are detailed and you can use Get-Help <cmdlet>.
# * Get-TaskUsers requires PowerShell be run elevated.
#

# FUNCTION LIST ###########################################################
#
# List users logged on to a machine or check for a specific user.
# Get-LoggedOn
#  [[-Name] <String>] 
#  [-CheckFor <String>] 
#  [-SupressNegative] 
#  [-ShowErrors] 
#  [<CommonParameters>] 
#
##
# List users being used to run services or check for a specific user.
# Get-ServiceUsers
#  [[-Name] <String>] 
#  [-CheckFor <String>] 
#  [-SupressNegative] 
#  [-ShowErrors] 
#  [<CommonParameters>]
#
##
# List users being used as the "Run As User" for tasks or cechk for a specific user.
# Get-TaskUsers
#  [[-Name] <String>] 
#  [-CheckFor <String>] 
#  [-SupressNegative] 
#  [-ShowErrors] 
#  [<CommonParameters>]
#
##
# List users and groups in a built-in group on a computer or check for a specific user.
# Get-LocalGroupMembers
#  [[-Name] <String>] 
#  -GroupName <String>
#  [-CheckFor <String>] 
#  [-SupressNegative] 
#  [-ShowErrors] 
#  [<CommonParameters>]
#
##
# As above, checks "Administrators" built in group.
# Get-Administrators
#  [[-Name] <String>] 
#  [-CheckFor <String>] 
#  [-SupressNegative] 
#  [-ShowErrors] 
#  [<CommonParameters>]
#
##
# As above, checks "Remote Desktop Users" built in group.
# Get-RDPUsers
#  [[-Name] <String>] 
#  [-CheckFor <String>] 
#  [-SupressNegative] 
#  [-ShowErrors] 
#  [<CommonParameters>]
#
##
# Copy users from one Active Directory group to another.
# Copy-GroupToGroup
#  [-Source] <String> 
#  [-Destination] <String>
#  [-ShowList]
#  [-ShowErrors]
#  [<CommonParameters>]
#
##
# Perform Get-LoggedOn, Get-ServiceUsers, and Get-TaskUsers against a single machine with a check for a specific user.
# Do-LockoutAudit
#  [[-User] <string>]
#  [[-CallerComputer] <string>]
#  [<WorkflowCommonParameters>]
#  [<CommonParameters>]
#

###########################################################################

<#
.Synopsis
   Get a list of users logged on to a computer or check for a specific user.

.DESCRIPTION
   Uses Query Session to list the active sessions on the local machine, a remote machine, or a list of remote machines or to check for a username against the list.

.PARAMETER Name
   A single or list of computer names to perform search against.

.PARAMETER CheckFor
   A username or partial username to check for in the list of logged on users.

.PARAMETER SupressNegative
   Do not show negative results for -CheckFor.

.PARAMETER ShowErrors
   Show all errors.

.EXAMPLE
   PS Z:\> Get-LoggedOn

   # BOBSMITH-PC - Logged on Users
    SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE 
    services                                    0  Disc                        
    console           BobSm                     1  Active                      
    rdp-tcp                                 65536  Listen                    

.EXAMPLE
   PS Z:\> Get-LoggedOn terminalserver01

   # terminalserver01 - Logged on Users
    SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE 
    services                                    0  Disc                        
    console                                     1  Conn                        
    rdp-tcp#0         BobSm                     2  Active  rdpwd               
                      JohnD                     3  Disc                        
                      JaneD                     4  Disc                                              
    rdp-tcp                                 65536  Listen        

.EXAMPLE
   PS Z:\> Get-LoggedOn terminalserver01 -CheckFor BobSm

   BobSm is logged on to terminalserver01
#>
function Get-LoggedOn
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Computer Name to Check
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Alias('ComputerName')]
        [string]$Name = $env:COMPUTERNAME,

        # Username to Check For
        [Parameter()]
        [string]$CheckFor,

        # Show negative results on CheckFor
        [parameter()]
        [switch]$SupressNegative,

        # Show all errors
        [parameter()]
        [switch]$ShowErrors
    )

    Begin
    {
        if (!$ShowErrors) 
        {
            #This stops PowerShell from showing connection failures when piping a large list of machines to the command.
            $ErrorActionPreference= 'silentlycontinue'
        }
    }
    Process
    {
        foreach ($computer in $name) 
        {
            $proc = qwinsta /server:$Computer | foreach {(($_.trim() -replace "\s+",","))} | ConvertFrom-Csv
            if ($CheckFor) 
            {
                ForEach ($p in $proc) 
                {
                    $temp = $p.SessionName
                    $temp2 = $p.Username

                    if ($temp -like "*$CheckFor*" -Or $temp2 -like "*$CheckFor*") 
                    {
                        write-host "$CheckFor is logged on to $Computer" -ForegroundColor green
                        $loggedon = 1
                    } 
                }

                if ($loggedon -ne 1 -and !$SupressNegative) 
                {
                        write-host "$CheckFor is not logged on to $Computer" -ForegroundColor red
                }
            } 
            elseif (!$CheckFor) 
            {
                Write-Host "`n# $Computer - Logged on Users"
                qwinsta /server:$Computer
            }
        }
    }
    End
    {
    }
}

<#
.Synopsis
   Get a list of users being used to run services on to a remote computer.

.DESCRIPTION

.PARAMETER Name
   A single or list of computer names to perform search against.

.PARAMETER CheckFor
   A username or partial username to check for in the results.

.PARAMETER SupressNegative
   Do not show negative results for -CheckFor.

.PARAMETER ShowErrors
   Show all errors.

.EXAMPLE
   PS Z:\> Get-ServiceUsers

   StartName                  
   ---------                  
                           
   LocalSystem                
   NT Authority\LocalService  
   NT AUTHORITY\NetworkService
      
.EXAMPLE
   PS Z:\> Get-ServiceUsers sqldb02

   StartName                         
   ---------                         
   localSystem                       
   NT AUTHORITY\LocalService         
   NT AUTHORITY\NetworkService       
   NT Service\MsDtsServer110         
   NT Service\MSSQLFDLauncher$SQL2K12
   serviceusr@my.domain.dom         
   dom\serviceusr2    

.EXAMPLE
   PS Z:\> Get-ServiceUsers sqldb02 -CheckFor serviceusr2

   dom\serviceusr2 is running MsDtsServer100 on sqldb02
   serviceusr2@my.domain.dom is running MSSQL$SQL2K12 on sqldb02
   dom\serviceusr2 is running MSSQL$SQL2K8R2 on sqldb02
   serviceusr2@my.domain.dom is running SQLAgent$SQL2K12 on sqldb02
   dom\serviceusr2 is running SQLAgent$SQL2K8R2 on sqldb02
#>
function Get-ServiceUsers
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Computer Name to Check
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Alias('ComputerName')]
        [string]$Name = $env:COMPUTERNAME,

        # Username to Check For
        [Parameter()]
        [string]$CheckFor,

        # Show negative results on CheckFor
        [parameter()]
        [switch]$SupressNegative,

        # Show all errors
        [parameter()]
        [switch]$ShowErrors
    )

    Begin
    {
        if (!$ShowErrors) 
        {
            #This stops PowerShell from showing connection failures when piping a large list of machines to the command.
            $ErrorActionPreference= 'silentlycontinue'
        }
    }
    Process
    {
        foreach ($computer in $name) 
        {
            $proc = Get-WmiObject -ComputerName $Computer win32_service | Select-Object Name,StartName
            if ($CheckFor) 
            {
                ForEach ($p in $proc) 
                {
	                $temp = $P.StartName
                    $temp2 = $P.Name
	  	            if ($temp -like "*$CheckFor*") 
                    {
			            write-host "$temp is running $temp2 on $Computer" -ForegroundColor green
                        $inlist = 1
                    }
                }
                if ($inlist -ne 1 -and !$SupressNegative) 
                {
                        write-host "$CheckFor is not running any services on $Computer" -ForegroundColor red
                }
            
            } 
            elseif (!$CheckFor) 
            {
                Get-WmiObject -ComputerName $Computer win32_service | Select-Object StartName | Sort-Object StartName -Unique
            }
        }
    }
    End
    {
    }
}

<#
.Synopsis
   Get a list of users in a specified local group.

.DESCRIPTION

.PARAMETER Name
   A single or list of computer names to perform search against.

.PARAMETER GroupName
   The group the query.

.PARAMETER CheckFor
   A username or partial username to check for in the results.

.PARAMETER SupressNegative
   Do not show negative results for -CheckFor.

.PARAMETER ShowErrors
   Show all errors.
   
.EXAMPLE
   PS Z:\> Get-LocalGroupMembers sqldb02 -GroupName Administrators

   # sqldb02 - Administrators
   sqldb02\Administrator
   dom\Domain Admins
   dom\JohnD
   dom\BobSm
   dom\DB_Admins

.EXAMPLE
   PS Z:\> Get-LocalGroupMembers sqldb02 -GroupName Administrators -CheckFor BobSm

   BobSm is listed in the Administrators group on sqldb02.

#>
function Get-LocalGroupMembers
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Computer Name to Check
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Alias('ComputerName')]
        [string]$Name = $env:COMPUTERNAME,
		
		[Parameter(Mandatory=$true)]
        [string]$GroupName,

        # Username to Check For
        [Parameter()]
        [string]$CheckFor,

        # Show negative results on CheckFor
        [parameter()]
        [switch]$SupressNegative,

        # Show all errors
        [parameter()]
        [switch]$ShowErrors
    )

    Begin
    {
        if (!$ShowErrors) 
        {
            #This stops PowerShell from showing connection failures when piping a large list of machines to the command.
            $ErrorActionPreference= 'silentlycontinue'
        }
    }
    Process
    {
        foreach ($computer in $name) 
        {
            $check = Gwmi win32_groupuser –computer $computer  
            $check = $check | Where-Object {$_.groupcomponent –match ".*$GroupName.*"} 
            if ($CheckFor) {
                if ($check -like "*$CheckFor*") 
                {
                    Write-Host "$CheckFor is listed in the $GroupName group on $computer." -ForegroundColor Green
                } 
                elseif ($check -notlike "*$CheckFor*" -and !$SupressNegative) 
                {
                    Write-Host "$CheckFor is not directly listed in the $GroupName group on $computer." -ForegroundColor Red
                }
            
            } 
            elseif (!$CheckFor) 
            {
                Write-Host "`n# $Computer - $GroupName"
                $check | ForEach-Object 
                {
                    $_.partcomponent –match “.+Domain\=(.+)\,Name\=(.+)$” > $nul 
                    $matches[1].trim('"') + “\” + $matches[2].trim('"') 
                } 
            }
        }
    }
    End
    {
    }
}

<#
.Synopsis
   Get a list of users in the .\Administrators group on a system.

.DESCRIPTION
   
.PARAMETER Name
   A single or list of computer names to perform search against.

.PARAMETER CheckFor
   A username or partial username to check for in the results.

.PARAMETER SupressNegative
   Do not show negative results for -CheckFor.

.PARAMETER ShowErrors
   Show all errors.

.EXAMPLE
   PS Z:\> Get-Administrators sqldb02

   # sqldb02 - Administrators
   sqldb02\Administrator
   dom\Domain Admins
   dom\JohnD
   dom\BobSm
   dom\DB_Admins

.EXAMPLE
   PS Z:\> Get-Administrators sqldb02 -CheckFor BobSm

   BobSm is listed in the Administrators group on sqldb02.
#>
function Get-Administrators
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Computer Name to Check
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Alias('ComputerName')]
        [string]$Name = $env:COMPUTERNAME,

        # Username to Check For
        [Parameter()]
        [string]$CheckFor,

        # Show negative results on CheckFor
        [parameter()]
        [switch]$SupressNegative,

        # Show all errors
        [parameter()]
        [switch]$ShowErrors
    )

    Begin
    {
        if (!$ShowErrors) 
        {
            #This stops PowerShell from showing connection failures when piping a large list of machines to the command.
            $ErrorActionPreference= 'silentlycontinue'
        }

        # Group being sent to Get-LocalGroupMembers
        $Group = "Administrators"
    }
    Process
    {
        foreach ($computer in $name) 
        {
            if ($CheckFor -and !$SupressNegative) 
            {
                Get-LocalGroupMembers $computer -CheckFor $CheckFor -GroupName $Group
            } 
            if ($CheckFor -and $SupressNegative) 
            {
                Get-LocalGroupMembers $computer -CheckFor $CheckFor -GroupName $Group -SupressNegative
            } 
            elseif (!$CheckFor) 
            {
                Get-LocalGroupMembers $computer -GroupName $Group
            }
        }
    }
    End
    {
    }
}

<#
.Synopsis
   Get a list of users in the .\Remote Desktop Users group on a system.

.DESCRIPTION
   
.PARAMETER Name
   A single or list of computer names to perform search against

.PARAMETER CheckFor
   A username or partial username to check for in the results.

.PARAMETER SupressNegative
   Do not show negative results for -CheckFor.

.PARAMETER ShowErrors
   Show all errors.

.EXAMPLE
   PS Z:\> Get-RDPUsers sqldb02

   # sqldb02 - Remote Desktop Users
   sqldb02\Administrator
   dom\JaneD
   dom\DB_Users

.EXAMPLE
   PS Z:\> Get-RDPUsers sqldb02 -CheckFor JaneD

   JaneD is listed in the Remote Desktop Users group on sqldb02.
#>
function Get-RDPUsers
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Computer Name to Check
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Alias('ComputerName')]
        [string]$Name = $env:COMPUTERNAME,

        # Username to Check For
        [Parameter()]
        [string]$CheckFor,

        # Show negative results on CheckFor
        [parameter()]
        [switch]$SupressNegative,

        # Show all errors
        [parameter()]
        [switch]$ShowErrors
    )

    Begin
    {
        if (!$ShowErrors) 
        {
            #This stops PowerShell from showing connection failures when piping a large list of machines to the command.
            $ErrorActionPreference= 'silentlycontinue'
        }

        # Group being sent to Get-LocalGroupMembers
        $Group = "Remote Desktop Users"
    }
    Process
    {
        foreach ($computer in $name) 
        {
            if ($CheckFor -and !$SupressNegative) 
            {
                Get-LocalGroupMembers $computer -CheckFor $CheckFor -GroupName $Group
            } 
            if ($CheckFor -and $SupressNegative) 
            {
                Get-LocalGroupMembers $computer -CheckFor $CheckFor -GroupName $Group -SupressNegative
            } 
            elseif (!$CheckFor) 
            {
                Get-LocalGroupMembers $computer -GroupName $Group
            }
        }
    }
    End
    {
    }
}

<#
.Synopsis
   Copy members of one active directory group to another active directory group.

.DESCRIPTION
   Gets a list of users from the source group and adds them to the destination group. This function does not overwrite the existing members in the destination group nor remove them from the source group.

.PARAMETER Source
   Group with members you wish to copy from.

.PARAMETER Destination
   Group to copy to.

.PARAMETER ShowList
   Show the users who were copied.

.EXAMPLE
   PS Z:\> Copy-GroupToGroup -Source Toronto_Office -Destination All_Canada

   All users were copied from Toronto_Office to All_Canada

.EXAMPLE
   PS Z:\>  Copy-GroupToGroup -Source Toronto_Office -Destination All_Canada -ShowList

   The following users were copied from Toronto_Office to All_Canada
       BobSm
       JohnD
       JaneD
#>
function Copy-GroupToGroup
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Source: Group from which members will be copied.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$false,
                   Position=0)]
        [String]$Source,

        # Destination(Dest): Group to which members will be copied
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$false,
                   Position=1)]
        [Alias("Dest")]
        [String]$Destination,

        # ShowList: Show a list of the users who were copied.
        [parameter()]
        [Switch]$ShowList,

        # Show all errors
        [parameter()]
        [switch]$ShowErrors
    )

    Begin
    {
    }
    Process
    {
        $Users = Get-ADGroupMember -Identity $Source | select samAccountName

        ForEach ($User in $Users) 
        {
            Add-ADGroupMember -Identity $Destination -Members $User
        }

        if ($ShowList) 
        { 
            Write-Host "The following users were copied from $Source to $Destination" -ForegroundColor Green
            ForEach ($User in $Users) 
            {
                $Display = $User.samAccountName
                Write-Host "    $Display"
            }
        } 
        elseif (!$ShowList) 
        {
            Write-Host "All users were copied from $Source to $Destination" -ForegroundColor Green
        }
    }
    End
    {
    }
}
<#
.Synopsis
   Get a list of users being used to run tasks on a remote computer.

.DESCRIPTION
    Queries remote computers for the users being used to run tasks in Task Scheduler. Can also be used to check for specific users.

.PARAMETER Name
   A single or list of computer names to perform search against.

.PARAMETER CheckFor
   A username or partial username to check for in the results.

.PARAMETER SupressNegative
   Do not show negative results for -CheckFor.

.PARAMETER ShowErrors
   Show all errors.

.EXAMPLE
   PS C:\Windows\system32> Get-TaskUsers
   The following unique users were found to be running tasks on BOBSMITH-PC
        INTERACTIVE
        LOCAL SERVICE
        NETWORK SERVICE
        BobSm
        SYSTEM
      
.EXAMPLE
   PS Z:\> Get-TaskUsers sqldb01
   The following unique users were found to be running tasks on sqldb01
        Administrators
        Everyone
        INTERACTIVE
        LOCAL SERVICE
        NETWORK SERVICE
        Run As User
        SYSTEM
        Users
        DOM\SVC-Backup

.EXAMPLE
   PS Z:\> Get-TaskUsers sqldb01 -CheckFor SVC-Backup
   
   DOM\SVC-Backup is being used to run "\Robocopy to backup09" on sqldb01. [ Task Status: Ready ]
#>
function Get-TaskUsers
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Computer Name to Check
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Alias('ComputerName')]
        [string]$Name = $env:COMPUTERNAME,

        # Username to Check For
        [Parameter()]
        [string]$CheckFor,

        # Do not show negative results on CheckFor
        [parameter()]
        [switch]$SupressNegative,

        # Show all errors
        [parameter()]
        [switch]$ShowErrors
    )

    Begin
    {
        if (!$ShowErrors) 
        {
            #This stops PowerShell from showing connection failures when piping a large list of machines to the command.
            $ErrorActionPreference= 'silentlycontinue'
        }
    }
    Process
    {
        foreach ($computer in $name) 
        {
            if ($CheckFor) 
            {
                $schtask = schtasks.exe /query /s $Name /V /FO CSV | ConvertFrom-Csv | Select TaskName,Author,"Task To Run","Run As User",Status
                ForEach ($p in $schtask) {
                    $temp = $p."Run As User"
                    $temp2 = $p.TaskName
                    $temp3 = $p.status

                    if ($temp -like "*$CheckFor*") 
                    {
                        Write-Host "$temp is being used to run ""$temp2"" on $computer."'['"Task Status: $temp3"']' -ForegroundColor Green
                        $taskuser = 1
                    }
                }

                if ($taskuser -ne 1 -and !$SupressNegative) 
                {
                    Write-Host "$CheckFor was not found to be running any tasks on $computer." -ForegroundColor Red
                }
            } 
            elseif (!$CheckFor) 
            {
                $Users = schtasks.exe /query /s $Name /V /FO CSV | ConvertFrom-Csv | Select "Run As User" | Sort-Object "Run As User" -Unique
                Write-Host "The following unique users were found to be running tasks on $Computer"
                foreach ($user in $users) 
                {
                    Write-Host '    '$user."Run as User"
                }
            }
        }
    }
    End
    {
    }
}

<#
.Synopsis
   Perform Get-TaskUsers, Get-ServiceUsers, Get-LoggedOn against a single machine checking for a particular user.

.DESCRIPTION
   When you have frequent lockouts for a particular user and identify a caller computer using EventID:4740 on the domain controller this script allows you to check for some of the more common causes of lockouts against that machine.

   This workflow checks to see if the user is running any tasks on the machine, is running any services on the machine, or has any stale sessions on the machine.

.EXAMPLE
   PS Z:\> Do-LockoutAudit -User BobSm -CallerComputer TerminalServer01

   BobSm is logged on to TerminalServer01
   BobSm is not running any services on TerminalServer01
   BobSm was not found to be running any tasks on TerminalServer01
#>
workflow Do-LockoutAudit 
{
    Param
    (
        # User who is being locked out.
        [Parameter(Mandatory=$true,
                   Position=0)]
        [String]
        $User,

        # Caller Computer.
        [Parameter(Mandatory=$true,
                   Position=1)]
        [Alias('Computer')]
        [string]
        $CallerComputer
    )

    parallel 
    {
        Get-TaskUsers -Name $CallerComputer -CheckFor $User
        Get-ServiceUsers -Name $CallerComputer -CheckFor $User
        Get-LoggedOn -Name $CallerComputer -CheckFor $User
    }

}