<#
	
	On Null Email Addresses

		If the user has no email address specififed the script will check extensionAttribute6 for an 
		email address. If extensionAttribute6 is null $DefaultTo will be used instead.

		You should place an email address in extensionAttribute6 for service accounts and admin accounts 
		that do not have their own email address.

#>

#########################################################################
# User Variables
#########################################################################
# Max password age in days.
# Set to 'Auto' and the script will use Get-ADDefaultDomainPasswordPolicy
# ie, $MaxPasswordAge = 'Auto'
$MaxPasswordAge = 90

# Days out from expiry on which to send emails as an array.
# ie, (5, 2, 1) will send emails if the password is set to expire in 5 days, 2 days, or 1 day.
$SendEmails = @(10, 5, 4, 3, 2, 1)

# Email Variables
$MailFrom = "passwords@company.com" # Send email from
$MailSMTPServer = "10.25.25.25" # Send email via
$DefaultTo = "itteam@company.com" # Send email here if user has no email address and extensionAttribute6 is null or an invalid address.

# Subject and Body - {0} replaces with number of days, {1} replaces with the user's full name.
$MailSubject = "Your Password is Set to Expire in {0} Days"

$MailBody = @"
Good Morning,

The network password for {1} will expire in {0} days. Please change your password as soon as possible using the instructions below.

From a computer on our network:
1. Press Ctrl+Alt+Delete on your keyboard.
2. Select "Change Password" from the menu.
3. Enter your old password in the top box.
4. Enter and confirm your new password.
5. Click "Change."

Complexity requirements:
- Your password must be at least 15 characters in length.
- Your password must contain three of the follow four types of characters: lowercase letters, uppercase letters, numbers, and special characters (i.e. $, @, *, !)
- Your password may not be one of the last 5 passwords you have used.
- Your password may not contain your first name, last name, or username.

Regards,
IT Support
"@



#########################################################################
# Static Variables - Do Not Change
#########################################################################
# $ExpiringDays needs to be one higher that the highest number in $SendEmails
$ExpireDays = $($SendEmails | Measure-Object -Maximum).Maximum
$ExpireDays++

# Date values.
$Today = Get-Date
$RangeDate = Get-Date (Get-Date).AddDays($ExpireDays)

# Automatic $MaxPasswordAge
if ($MaxPasswordAge -eq "Auto")
{
	$MaxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
}

# Create the output aaray.
$Output = @()

#########################################################################
# Script Logic
#########################################################################
# Send email function.
function Send-ExpireEmail ($To, $From, $SMTPServer, $Subject, $Body, $Days, $Name)
{
	$Msg = New-Object Net.Mail.MailMessage
	$SMTP = New-Object Net.Mail.SMTPClient($SMTPServer)
	$Msg.From = "$From"
	$Msg.ReplyTo = "$From"
	$Msg.To.Add($To)
	$Msg.Subject = $Subject -f $Days, $Name
	if ($Days -eq "1")
	{
		$Msg.Subject = $($Msg.Subject) -ireplace "Days", "Day"
	}
	$Msg.Body = $Body -f $Days, $Name
	if ($Days -eq "1")
	{
		$Msg.Body = $($Msg.Body) -ireplace "Days", "day"
	}
	$SMTP.Send($Msg)
}

# Find expiring users that match criteria.
$Users = Get-ADUser -Properties PasswordLastSet, PasswordNeverExpires, EmployeeType, Mail, extensionAttribute6 -Filter 'PasswordNeverExpires -eq $False' | Where-Object {
	($_.PasswordLastSet -ne $NULL) -and ($_.Enabled -eq $True) -and ($_.PasswordLastSet.AddDays($MaxPasswordAge) -le $RangeDate) -and ($_.PasswordLastSet.AddDays($MaxPasswordAge) -ge $Today)
}

# Determine attributes and whether or not to send email based on $SendEmail
foreach ($User in $Users)
{
	$ExpireDate = $User.PasswordLastSet.AddDays($MaxPasswordAge)
	
	$Span = New-TimeSpan -End $ExpireDate -Start $Today
	
	if ($($Span.Days) -in $SendEmails)
	{
		
		if ($User.Mail -eq $null -and $User.extensionAttribute6 -eq $null)
		{
			$MailTo = $DefaultTo
		}
		elseif ($User.Mail -eq $null -and $User.extensionAttribute6 -match "^(?("")("".+?""@)|(([0-9a-zA-Z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-zA-Z])@))(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,6}))$")
		{
			$MailTo = $User.extensionAttribute6
		}
		else
		{
			$MailTo = $User.Mail
		}
		
		$Output += New-Object -TypeName PSObject -Property @{
			Name = $User.Name
			Email = $MailTo
			Expires = $User.PasswordLastSet.AddDays(90)
			Span = $Span.Days
		}
	}
}

# Per-user that meets criteria: send emails.
foreach ($ExpiringUser in $Output)
{
	#Call Send-ExpireEmail
	Send-ExpireEmail -To $($ExpiringUser.Email) -From $MailFrom -SMTPServer $MailSMTPServer -Subject $MailSubject -Body $MailBody -Days $($ExpiringUser.Span) -Name $($ExpiringUser.Name)
}

# Use for testing
# Comment out foreach loop above to supress emails while testing.
## $Output | Sort-Object span | Format-Table