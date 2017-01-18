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
# 17/1/2017 - Nick James <omniomi>
#     - Get-LoggedOn and Get-ServiceUsers rewritten to be object oriented.
#
# 18/1/2017 - Nick James <omniomi>
#	  - Improvements to Get-ServiceUsers output.
#
    
# NOTES ###################################################################
#
# * All cmdlets are detailed and you can use Get-Help <cmdlet>.
# * Get-TaskUsers requires PowerShell be run elevated.
#

###########################################################################

<#
	.SYNOPSIS
		List the users that are logged on to a computer or check for a specific user.

	.DESCRIPTION
		This function uses the CMD application query.exe to list the users on the local system, a remote system, or a group of remote systems. It converts the query.exe objects.

		When using the -CheckFor parameter you are able to check for a specific user and the function will return true/false.

	.PARAMETER  Name
		The computer name to be queried. 

	.PARAMETER  CheckFor
		A specific username to look for.

	.EXAMPLE
		PS C:\> Get-LoggedOn

		ComputerName Username SessionState SessionType
		------------ -------- ------------ -----------
		JDOE-Laptop  JohnD    Active       console

		- Description - 
		In this example without parameters the command returns locally logged in users.

	.EXAMPLE
		PS C:\> Get-LoggedOn -Name TERMSERV01

		ComputerName Username  SessionState SessionType
		------------ --------  ------------ -----------
		TERMSERV01   JaneD     Disconnected
		TERMSERV01   JamesR    Disconnected
		TERMSERV01   ToddQ     Active        rdp-tcp
		TERMSERV01   BrianZ    Disconnected

		- Description - 
		When a computer name is specific you will se a list of users that are connected to that machine.

	.EXAMPLE
		PS C:\> Get-LoggedOn -Name TERMSERV01 -CheckFor JaneD

		ComputerName IsLoggedOn
		------------ ----------
		TERMSERV01         True

		- Description - 
		CheckFor allows you to check for a specific user on a remote machine.

	.EXAMPLE
		PS C:\> Get-LoggedOn -Name NONEXISTENT -CheckFor JaneD

		ComputerName IsLoggedOn
		------------ ----------
		NONEXISTENT  [ERROR]

		- Description - 
		If query.exe cannot access the compute for any reason it will return [ERROR]

	.EXAMPLE
		PS C:\> Get-ADComputer -Filter 'name -like "TERMSERV*"' | Get-LoggedOn -CheckFor JaneD

		ComputerName   IsLoggedOn
		------------   ----------
		TERMSERV01          False
		TERMSERV02           True
		TERMSERV03          False

		- Description - 
		You can pipe a list of computers to check multiple machines at the same time.

	.INPUTS
		System.String

	.OUTPUTS
		PSCustomObject

#>

function Get-LoggedOn
{
	[CmdletBinding()]
	[Alias('loggedon')]
	[OutputType([PSCustomObject])]
	Param
	(
		# Computer name to check
		[Parameter(ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 0)]
		[Alias('ComputerName')]
		[string]
		$Name = $env:COMPUTERNAME,
		# Username to check against logged in users.

		[parameter()]
		[string]
		$CheckFor
	)
	
	Process
	{
		function QueryToObject ($Computer)
		{
			$Output = @()
			$Users = query user /server:$Computer 2>&1
			if ($Users -like "*No User exists*")
			{
				$Output += [PSCustomObject]@{
					ComputerName = $Computer
					Username = $null
					SessionState = $null
					SessionType = "[None Found]"
				}
			}
			elseif ($Users -like "*Error*")
			{
				$Output += [PSCustomObject]@{
					ComputerName = $Computer
					Username = $null
					SessionState = $null
					SessionType = "[Error]"
				}
			}
			else
			{
				$Users = $Users | ForEach-Object {
					(($_.trim() -replace ">" -replace "(?m)^([A-Za-z0-9]{3,})\s+(\d{1,2}\s+\w+)", '$1  none  $2' -replace "\s{2,}", "," -replace "none", $null))
				} | ConvertFrom-Csv
				
				foreach ($User in $Users)
				{
					$Output += [PSCustomObject]@{
						ComputerName = $Computer
						Username = $User.USERNAME
						SessionState = $User.STATE.Replace("Disc", "Disconnected")
						SessionType = $($User.SESSIONNAME -Replace '#', '' -Replace "[0-9]+", "")
					}
					
				}
			}
			return $Output | Sort-Object -Property ComputerName
		}
		
		if ($CheckFor)
		{
			$Usernames = @()
			$Sessions = @()
			$Result = @()
			$Users = QueryToObject -Computer $Name
			
			foreach ($User in $Users)
			{
				$Usernames += $User.Username
				$Sessions += $User.SessionType
			}
			
			if ("[Error]" -in $Sessions)
			{
				$Result += [PSCustomObject]@{
					ComputerName = $Name
					IsLoggedOn = "[ERROR]"
				}
			}
			elseif ($CheckFor -in $Usernames -and "[*]" -notin $Sessions)
			{
				$Result += [PSCustomObject]@{
					ComputerName = $Name
					IsLoggedOn = $true
				}
			}
			else
			{
				$Result += [PSCustomObject]@{
					ComputerName = $Name
					IsLoggedOn = $false
				}
			}
			return $Result | Select-Object ComputerName, IsLoggedOn
		}
		elseif (!$CheckFor)
		{
			$Result = QueryToObject -Computer $Name
			return $Result
		}
	}
	
}

<#
.Synopsis
	Get a list of unique usernames being used to run services on a computer.

.DESCRIPTION
	Get a list of unique user's being used to run services on one or more computers. 

.PARAMETER Name
	A single or list of computer names to perform search against. Accepts piped input.

.EXAMPLE
	PS C:\> Get-ServiceUsers

	Computer  Domain       Username       Services
	--------  ------       --------       --------
	BSMITH-LT              LocalSystem    {AdobeARMservice, AdobeUpdateService, AGSService, AMD External Events Utility...}
	BSMITH-LT NT AUTHORITY LocalService   {AJRouter, ALG, AppIDSvc, Audiosrv...}
	BSMITH-LT NT AUTHORITY NetworkService {aspnet_state, CryptSvc, Dnscache, Fax...}
      
.EXAMPLE
	PS C:\> Get-ServiceUsers -Name SERVERDB11

	Computer   Domain        Username                Services
	--------   ------        --------                --------
	SERVERDB11               LocalSystem             {AeLookupSvc, Appinfo, AppMgmt, AudioEndpointBuilder...}
	SERVERDB11 NT AUTHORITY  LOCALSERVICE            {ALG, AppIDSvc, AudioSrv, BFE...}
	SERVERDB11 NT AUTHORITY  NetworkService          {AdtAgent, aspnet_state, CryptSvc, Dnscache...}
	SERVERDB11 NT SERVICE    MsDtsServer110          {MsDtsServer110}
	SERVERDB11 NT SERVICE    MSSQLFDLauncher$SQL2K12 {MSSQLFDLauncher$SQL2K12}
	SERVERDB11 DOM.CORP.COM  sqlusr2                 {MSSQL$SQL2K12, SQLAgent$SQL2K12}
	SERVERDB11 DOM           sqladmin1               {MsDtsServer100, MSSQL$SQL2K8R2, SQLAgent$SQL2K8R2} 

.EXAMPLE
	PS C:\> Get-ServiceUsers -Name SERVERDB11 | Where-Object {$_.Domain -like "DOM*"}

	Computer   Domain        Username  Services
	--------   ------        --------  --------
	SERVERDB11 DOM.CORP.COM  sqlusr2   {MSSQL$SQL2K12, SQLAgent$SQL2K12}
	SERVERDB11 DOM           sqladmin1 {MsDtsServer100, MSSQL$SQL2K8R2, SQLAgent$SQL2K8R2}

	PS C:\> Get-ADComputer -Filter 'Name -Like "SERVERDB*"' | Get-ServiceUsers | Where-Object {$_.Domain -like "DOM*"} | Select Computer,Domain,Username

.EXAMPLE
	Computer   Domain        Username
	--------   ------        --------
	SERVERDB11 DOM.CORP.COM  sqlusr2
	SERVERDB11 DOM           sqladmin1
	SERBERDB14 DOM			 sqlusr2


#>
function Get-ServiceUsers
{
	[CmdletBinding()]
	[Alias()]
	[OutputType([PSCustomObject])]
	Param
	(
		# Singluar computer or list of computers to query. Accepts input from pipeline.
		# Default value if -Name unspecified is localhost ($env:COMPUTERNAME).
		[Parameter(ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 0)]
		[Alias('ComputerName')]
		[string]
		$Name = $env:COMPUTERNAME
	)
	
	begin
	{
		# Verbose output.
		Write-Verbose "Writing sub-functions to memory."
		
		# Split-Username splits down-level and upn format usernames in to domain and username.
		function Split-Username ($Username)
		{
			# Deal with down-level usernames (domain\samaccountname).
			if ($Username -like "*\*")
			{
				$Useroutput = [pscustomobject]@{
					domain = $Username.Split('\')[0].ToUpper()
					username = $Username.Split('\')[1]
				}
			}
			# Deal with UPNs (usernames@domain).
			elseif ($Username -like "*@*")
			{
				$Useroutput = [pscustomobject]@{
					domain = $Username.Split('@')[1].ToUpper()
					username = $Username.Split('@')[0]
				}
			}
			# Deal with all else.
			else
			{
				$Useroutput = [pscustomobject]@{
					domain = $null
					username = $Username
				}
			}
			# Return split.
			return $Useroutput
		}
	}
	
	Process
	{
		# Error handling for WMI Query. Will trap errors.
		try
		{
			# Verbose output.
			Write-Verbose "Querying WMI win32_service on $Name."
			
			# Query computer for services to $Proc.
			$Proc = Get-WmiObject -ComputerName $Name win32_service -ErrorAction Stop | Select-Object Name, StartName
		}
		catch
		{
			# Error message and error message shortened to variables.
			$ErrorText = $Error[0].Exception.Message
			$ErrorShortText = $ErrorText.ToString().Split('(')[0]
			
			# Verbose and error output.
			Write-Verbose "Could not talk to $Name : $ErrorShortText"
			Write-Error "Could not talk to $Name : $ErrorText"
			
			return
		}
		finally
		{
			# Clear error variable.
			$Error.Clear()
		}
		
		
		# Determine all unique usernames in $Proc.
		Write-Verbose "Determining unique users being used to run services on $Name."
		$UniqueUsers = $Proc | Select-Object StartName | Where-Object {
			$_.StartName -ne $null
		} | Sort-Object StartName -Unique
		
		# Loop through unique usernames.
		foreach ($ServiceUsername in $UniqueUsers)
		{
			# Define $ServiceList as an array.
			$ServiceList = @()
			
			# Determine which services are being run by the current user being processed.
			# Output to $ServiceList.
			Write-Verbose "Listing services being run by $($ServiceUsername.StartName) on $Name."
			$ServicesByUser = $Proc | Select-Object StartName, Name | Where-Object {
				$_.StartName -like $ServiceUsername.StartName
			}
			foreach ($Service in $ServicesByUser)
			{
				;
				$ServiceList += "$($Service.Name)"
			}
			
			# Run the StartName property through Split-Username to get domain and username as separate properties.
			Write-Verbose "Formatting username $($ServiceUsername.StartName)."
			$Split = Split-Username $ServiceUsername.StartName
			$Username = $Split.Username
			$Domain = $Split.Domain
			
			# Generate Output.
			Write-Verbose "Outputting details for $($ServiceUsername.StartName) on $Name"
			[PSCustomObject]@{
				Computer = $Name
				Domain = $Domain
				Username = $Username
				Services = $ServiceList
			}
		}
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