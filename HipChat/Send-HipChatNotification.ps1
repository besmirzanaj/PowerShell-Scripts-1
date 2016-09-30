<#
.Synopsis
   Send a message to a HipChat room using the V2 API.
   Authentication by token required, with scope send_notification.

.PARAMETER HipChatURL
   The base url for HipChat. Example: api.hipchat.com
   Do not include https:// or the trailing slash. (Stripped if entered)

   Defaults to 'api.hipchat.com'.
   
.PARAMETER Token
   The API Token with scope send_notification. Generated at: <hipchat url>/rooms/tokens/<roomid>.

.PARAMETER RoomID
   The id or url encoded name of the room.

.PARAMETER From
   A label to be shown in addition to the sender's name. (Max Length: 64)

   The sender's name is defined by the label of the API Token and cannot be changed by this script.

.PARAMETER Color
   Background color for message.
   
   Valid values: yellow, green, red, purple, gray, random.
   Defaults to 'gray'.

.PARAMETER Message
   The message to be sent to the room. Use `n for new line and `t for tab. (Max Length: 10000)

.PARAMETER NotifyUsers
   Whether this message should trigger a user notification (change the tab color, play a sound, notify mobile phones, etc). Each recipient's notification preferences are taken into account.

.PARAMETER UseHTTP
   Send API request over http instead of https. 

.EXAMPLE
   Send-HipChatNotification -Token fIEaA8y28em0mNOVmGNTlN7IDBARoTAKMgg5c -RoomID 101 -Message "Hello World!" -NotifyUsers

.EXAMPLE
   Send-HipChatNotification -HipChatURL hipchat.mycompany.com -Token fIEaA8y28em0mNOVmGNTlN7IDBARoTAKMgg5c -RoomID 101 -From "MyScript" -Message "Error: Script Failed to Run." -Color Red -UseHttp
#>
function Send-HipChatNotification
{
    Param
    (
    # Hipchat Host
    [Parameter()]
    [String]
    $HipChatURL = "api.hipchat.com",

    # API Token
    [Parameter(Mandatory=$True)]
    [String]
    $Token,

    # The id or url encoded name of the room
    [Parameter(Mandatory=$True)]
    [String]
    $RoomID,

    # A label to be shown in addition to the sender's name (Max Length: 64)
    [Parameter()]
    [ValidateLength(0,64)]
    [String]
    $From,

    # Background color for message.
    [Parameter()]
    [ValidateSet("yellow","green","red","purple","gray","random")] 
    [Alias("Colour")]
    [String]
    $Color = "gray",

    # The message body (Max Length: 10000)
    [Parameter(Mandatory=$True)]
    [ValidateLength(1,10000)]
    [String]
    $Message,

    # Whether this message should trigger a user notification
    [Parameter()]
    [Switch]
    $NotifyUsers,

    # HipChat server uses http. Defaults to 'https'.
    [Parameter()]
    [Switch]
    $UseHttp
    )

    Begin
    {
        # URI Formatting
        ## Format URI  as expected
        if ($HipChatURL -match 'http[s]?\:\/\/[a-z0-9]+')
        {
            $Temp = [System.Uri]"$HipChatURL"
            $Domain = $Temp.Host
        }
        else 
        {
            $Domain = $HipChatURL
        }
        
        ## Https vs Http
        if ($UseHttp) 
        {
            $FullUri = "http://$Domain/v2/room/$RoomID/notification"
        }
        else
        {
            $FullUri = "https://$Domain/v2/room/$RoomID/notification"
        }

        # Create Array
        $Body = @{
                  auth_token = "$Token"
                  from = "$From"
                  color = "$Color"
                  message = "$Message"
                  notify = "$NotifyUsers"
                  message_format = "text"
                 }
    }

    Process
    {
        try
        {
            Invoke-RestMethod -method Post -Uri $FullUri -Body $body
        }
        catch
        {
            if ($_.Exception.Message -like "*(401) Unauthorized*")
            {
                Write-Error "Error 401: The authentication you provided is invalid. https://www.hipchat.com/docs/apiv2/auth"
            }
            elseif ($_.Exception.Message -like "*(403) Forbidden*")
            {
                Write-Error "Error 403: You don't have permission to complete the operation or access the resource. https://developer.atlassian.com/hipchat/guide/hipchat-rest-api/api-response-codes" 
            }
            elseif ($_.Exception.Message -like "*(404) Not Found*")
            {
                Write-Error "Error 404: You requested an invalid method. https://developer.atlassian.com/hipchat/guide/hipchat-rest-api/api-response-codes"
            }
            elseif ($_.Exception.Message -like "*(429) Too Many Requests*")
            {
                Write-Error "Error 429: You have exceeded the rate limit. https://www.hipchat.com/docs/apiv2/rate_limiting"
            }
            else 
            {
                Write-Error $_.Exception.Message
            }
        }
    }

    End
    {
    }
}