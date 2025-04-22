<#
 .Synopsis
  Returns a security token to the user.

 .Description
  This module will attempt to login to a APC NMC interface and if successful, it will return a valid security token for future requests to the host.

 .Parameter Target
  The FQDN or IP address of the web interface in which a login attempt will be made against.

 .Parameter Username
  The username used for the login attempt.

 .Parameter Password
  The password used for the login attempt.

 .Parameter Protocol
  The protocol (HTTP/HTTPS) used when making requests to the Target, this defaults to HTTP but can be overwritten.

 .Example
   # Get security token for a NMC interface.
   Get-APCNMCToken -Target mypdu.domain.com -User john -Password smith

 .Example
   # Get security token for a NMC interface with HTTPS.
   Get-APCNMCToken -Target mypdu.domain.com -User john -Password smith -Protocol HTTPS
#>

function Get-APCNMCToken {

    param(
        [Parameter(Mandatory)]
        [string] $Target,

        [Parameter(Mandatory)]
        [string] $Username,

        [Parameter(Mandatory)]
        [string] $Password,

        [string] $Protocol = "https"
    )

    # Some variables to help us along the way
    $NMCString = $null

    # APC Discovery
    $url = "$($Protocol)://$($Target)"

    Try {
        $discovery = Invoke-WebRequest $url -Method GET -SessionVariable session -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
    }

    $stringSplit = $($discovery.BaseResponse.ResponseUri.AbsoluteUri.Split('/')[4])

    if($discovery.StatusCode -eq 200 -and $stringSplit) { 
        # Update our object properties
        $NMCString = "$($Protocol)://$($Target)/NMC/$($stringSplit)"
    }

    $loginActionUri = "$($NMCString)/Forms/login1" 
        
    # Initial payload for logging in
    $loginRequestPostParams = @{
        'prefLanguage' = '00000000'
        'login_username' = $Username
        'login_password' = $Password
        'submit' = 'Log+On'
    }

    # Invoke-WebRequest parameters
    $logonRequestSplat = @{
        Uri = $loginActionUri
        SessionVariable = 'session'
        Method = 'Post'
        Body = $loginRequestPostParams
        ContentType = 'application/x-www-form-urlencoded'
        UseBasicParsing = $true
    }

    # Make the initial logon request
    $request = Invoke-WebRequest @logonRequestSplat

    if ($request.StatusCode -eq 200 -notcontains $request.RawContent.Contains("Invalid")) { 
        # HTML DOM
        $dom = $request.Content

        # Regular expression to extract the value we require
        $regex = [RegEx]::Matches($dom, '\/NMC\/(.*?)\/')

        # Return token to user
        return $regex.Groups[1].Value
    }

    # If we fail to login, document it.
    if($request.StatusCode -eq 403 -or $request.RawContent.Contains("Invalid")) {
        Write-Host "Unable to login, bad username / password combination or other." -ForegroundColor Red
        return
    }

}
Export-ModuleMember -Function Get-APCNMCToken
