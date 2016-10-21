<#	
	.NOTES
	===========================================================================
	 Created by:   	NickJ
	 Filename:     	ADGroupMonitor.ps1
	===========================================================================
	.DESCRIPTION
		On first run this script creates a CSV file containing the members of
	the groups specified and on subsequent runs compares the group members to 
	the CSV. If there are changes between the group and the CSV it sends an
	email and then updates the csv file for the next run.

		This solution is for situations where audit levels cannot be raised to
	show group changes in the security logs of a domain controller or where 
	there is no good way in place to monitor those logs such as SCOM.



	===========================================================================
	USER VARIABLES
	===========================================================================
#>

$ScriptPath = "C:\scripts" # This path must exist.

$SendFrom = "" # From and reply-to address for email notifications.
$SendTo = "" # Comma seperated list of addresses to send to.
$SMTPServer = "" # SMTP server hostname or IP.
$Subject = "[Group Change] A monitored group has been changed" # Email subject line for notifications.

# Array of groups to monitor - Newly added groups will be checked for changes on the second run.
$GroupsToMonitor = @(
	"Enterprise Admins",
	"Domain Admins",
	"Administrators",
    "Account Operators"
)

<#	
	===========================================================================
	DO NOT EDIT BELOW UNLESS YOU KNOW WHAT YOU'RE DOING.
	===========================================================================
#>

# Function to check group for changes.
function Check-Group
{
	param
	(
		[parameter(Mandatory = $true,
				   Position = 0)]
		[string]
		$GroupName
	)
	
	# Get group members
	$GroupMembers = Get-ADGroupMember -Identity $GroupName
	
	# Check for reference point
	$CheckForFile = Test-Path "$ScriptPath\groups\$GroupName.csv"
	
	# Create file if first run or file is missing and then stop
	if ($CheckForFile -eq $false)
	{
		$GroupMembers | Export-Csv "$ScriptPath\groups\$GroupName.csv"
	}
	else
	{
		$RefGroupMembers = Import-Csv "$ScriptPath\groups\$GroupName.csv"
	}
	
	# Compare current members to existing CSV file.
	$Compare = Compare-Object -ReferenceObject ($RefGroupMembers.SamAccountName | Sort-Object) -DifferenceObject ($GroupMembers.SamAccountName | Sort-Object)
	
	if ($Compare)
	{
		$Compare | ForEach-Object {
			if ($_.sideindicator -eq '<=')
			{
				$_.sideindicator = "removed"
			}
			
			if ($_.sideindicator -eq '=>')
			{
				$_.sideindicator = "added"
			}
		}
	}
	
	if ($Compare)
	{
		if (!$Changes)
		{
			$Changes = @()
		}
		
		foreach ($Change in $Compare)
		{
			$Changes += New-Object -TypeName System.Management.Automation.PSObject -Property @{
				GroupName = $GroupName
				Who = $Change.inputObject
				What = $Change.sideindicator
			} | Select-Object GroupName, Who, What
		}
		
		Write-Output $Changes
		
		# Update the CSV File
		$GroupMembers | Export-Csv "$ScriptPath\groups\$GroupName.csv"
	}
}

# Create CSV directory if missing.
$CheckCSVPath = Test-Path "$ScriptPath\Groups"

if ($CheckCSVPath -eq $false)
{
	New-Item "$ScriptPath\Groups" -ItemType directory
}

# Process each group in turn.
foreach ($Group in $GroupsToMonitor)
{
	$CheckGroup = Check-Group $Group
	if ($CheckGroup)
	{
		if (!$Changes)
		{
			$Changes = @()
		}
		
		$Changes += $CheckGroup	
	}
	
}

# Send mail if change detected.
if ($Changes)
{
	
	$Msg = New-Object Net.Mail.MailMessage
	$SMTP = New-Object Net.Mail.SMTPClient($SMTPServer)
	$Msg.From = "$SendFrom"
	$Msg.ReplyTo = "$SendFrom"
	$Msg.To.Add($SendTo)
	$Msg.Subject = $Subject
	$Msg.Body = "Hi,`n`nOne or more monitored active directory groups have been changed`n`nChanges:`n"
	foreach ($Change in $Changes)
	{
		$Group = $Change.GroupName
		$Who = $Change.Who
		$What = $Change.What
		$Name = Get-ADUser -Identity "$Who"
		$Name = $Name.Name
		if ($What -eq "Added")
		{
			$opr = "to"
		}
		else
		{
			$opr = "from"
		}
		$Msg.Body += "`t$Who ($Name) was $What $opr $Group `n"
	}
	$SMTP.Send($Msg)
}

