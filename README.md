# PowerShell-Scripts

Script Disclaimer:
The scripts provided here are not supported under any standard support program or service. All scripts are provided AS IS without warranty of any kind. The author disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall the author or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if the author has been advised of the possibility of such damages.

## ADGroupMonitor.ps1

Watches for changes in specified AD groups and sends an email notification if the group membership is changed.

This solution is for situations where audit levels cannot be raised to show group changes in the security logs of a domain controller or where there is no good way in place to monitor those logs such as SCOM.

On first run this script creates a CSV file containing the members of the groups specified and on subsequent runs compares the group members to the CSV. If there are changes between the group and the CSV it sends an email and then updates the csv file for the next run.

## ADPasswordExpiration.ps1

My take on generating emails to remind users that their password is going to expire. 

Features: 
- Can be configured to send emails reminding users only on specific days out from expiration. Ie: 10, 5, 2, 1
- Can be set to determine max password age automatically from your default domain policy.
- Includes a template email.

## Convert-FrenchCharacters.ps1

A basic function to convert French accented characters to their basic Latin equivalents. 

Example: François Gérard -> Francois Gerard

## Convert-QuerytoObjects.ps1

Converts the output of 'query.exe user' to usable objects.

This is unfortunately the most effective way of getting active and disconnected sessions from remote computers.

## Get-ServiceUsers.ps1

A standalone copy of Get-ServiceUsers from functions.ps1. 

Used to identify user accounts being used to run services on one or more remote computers.

## functions.ps1

Contains AD computer management and audting functions that allow you to:'

- Query logged on users for a local or remote computer and/or check for a specific user.
- Query users being used to run services on a local or remote computer and/or check for a specific user.
- Query the list of users in a group on a local or remote computer and/or check for a specific user. Ie, query the local administrators group and check to see if "Domain Users" is present.
- Copy members from one AD group to another.
- Query the users being used to run tasks in Task Scheduler and/or check for a specific user.

## HipChat/Send-HipChatNotification.ps1

Send a notification or message to a HipChat channel using PowerShell. Invokes a RESTful API call.