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
		if (-not (Test-Connection $Name -Count 1 -Quiet))
		{
			Write-Verbose "$Name failed to respond to ping. Skipping."
			Write-Error "Test-Connection : Test connection to computer '$Name' failed. Skipping service check."
			return
		}
		
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