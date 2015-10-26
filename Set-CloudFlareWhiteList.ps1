#requires -Version 3

<#
        .Synopsis
        White-list Tor Exit IP addresses in CloudFlare. This allows Tor users to access your websites without CAPTCHA requests
        
        .DESCRIPTION
        Many thanks to Donncha O'Cearbhaill for the development of his Cloudflare-tor-whitelister. Please visit: 
        https://github.com/DonnchaC/cloudflare-tor-whitelister. Without his work, this would not have been as achievable.
   
        CloudFlare creates a pretty poor user experience for Tor users. The issue stems from how CloudFlare protect 
        websites from attacks. When users visit a protected website, CloudFlare assigns a threat or risk score to their IP. 
        If an IP is safe, then the user gets to see your page. If an IP is suspicious, then the user will need to complete 
        a CAPTCHA, or in serious cases, denied access.

        Due to the high use of Tor for malicious activity, CloudFlare will be suspicious of known Tor exit nodes. 
        This suspicion results in Tor users experiencing repeated CAPTCHA requests. With CloudFlare's popularity, 
        Tor users experience these requests more and more.

        The aim of this script is to provide website operators with a way to white-list Tor exit IP addresses. 
        This script is adapted from Donncha O'Cearbhaill's CloudFlare-Tor-Whitelister, whitelist.py.
        
        .EXAMPLE
        Set-CloudFlareWhitelist.ps1 -Token $MyCloudFlareToken -Email $MyEmail
        Creates/updates rules for Tor Exit address accross all of your domains in CloudFlare
        
        .EXAMPLE
        Set-CloudFlareWhitelist.ps1 -Token $MyCloudFlareToken -Email $MyEmail -Zone contoso.com
        Creates/updates rules for Tor Exit IP addresses only for the domain contoso.com

        .EXAMPLE
        Set-CloudFlareWhitelist.ps1 -Token $MyCloudFlareToken -Email $MyEmail -ClearRules
        Remove all Tor Exit IP address rules specified for all of your domains in CloudFlare
        
        .NOTES
        AUTHOR: Kieran Jacobsen - Posh Security - http://poshsecurity.com
        KEYWORDS: DNS, CloudFlare, Posh Security, Tor, Exit Node
        THANKS:
        Donncha O'Cearbhaill
        Readify

        .LINK
        http://poshsecurity.com

        .LINK 
        https://github.com/poshsecurity/Posh-CloudFlareWhiteList

        .LINK
        https://github.com/DonnchaC/cloudflare-tor-whitelister
#>
[CmdletBinding()]
Param
(
    # CloudFlare API Token. Found on the Account page.
    [Parameter(Mandatory = $True, 
    Position = 0)]
    [ValidateNotNullOrEmpty()]
    [alias('t')]
    [String]
    $Token,

    # CloudFlare Email address. This is the email address you sign in with.
    [Parameter(Mandatory = $True, 
    Position = 1)]
    [ValidateNotNullOrEmpty()]
    [alias('e')]
    [String]
    $Email,

    # DNS Zone. Optional. If not specified, rules will apply to all zones.
    [Parameter(Mandatory = $False, 
    Position = 2)]
    [ValidateNotNullOrEmpty()]
    [alias('z')]
    [String]
    $Zone = '',

    # Remove all tor_exit rules, do not create/update
    [Parameter(Mandatory = $False)]
    [alias('clear-rules')]
    [Switch]
    $ClearRules,

    # Number of rules to create in Cloudflare. Defaults to 200. Optional.
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [alias('rule-limit')]
    [Int]
    $RuleLimit = 200
)

Set-StrictMode -Version Latest




<#
        TOR Functions
        -------------
#>
function Get-TopTorExitNodeIPAddress
{
    [CmdletBinding()]
    [OutputType([String[]])]
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [int]
        $Limit
    )

    # As in orgiginal, get some extra IP addresses (I double the limit)
    $FatLimit = $Limit * 2
    Write-Verbose -Message ('Fat limit is {0}' -f $FatLimit)

    # We only want running exit nodes, and we only need the address and exit probability (we order by consensus weight)
    $Data = @{
        'running' = 'True'
        'flag'    = 'Exit'
        'fields'  = 'or_addresses,exit_probability'
        'order'   = '-consensus_weight'
        'limit'   = $FatLimit
    }

    try
    {
        $OnionOODetails = Invoke-RestMethod -Uri 'https://onionoo.torproject.org/details' -Method Get -Body $Data -ErrorAction Stop
    }
    catch
    {
        $MyError = $_
        Throw $MyError
    }
    
    Write-Verbose -Message ('Number of relays returned {0}' -f ($OnionOODetails.relays | Measure-Object).Count)
    Write-Debug -Message 'Building list of IP addresses'

    # Build an array list of just the IP addresses (removing port numbers)
    $IPAddressList = @()
    foreach ($Relay in $OnionOODetails.relays)
    {
        foreach ($Address in $Relay.or_addresses)
        {
            # IPv6 addresses have [] around them, so we need to trim them up before removing TCP port number
            if ($Address.contains('['))
            {
                # IPV6
                # Currently commented out (so we don't make use of them). 
                # Previously the API did allow IPv6, but it seems this has changed.
                #$IPAddress = $Address.split(']')[0].trim('[')
                #$IPAddressList += $IPAddress
            }
            else
            {
                #IPV4
                $IPAddress = $Address.split(':')[0]
                $IPAddressList += $IPAddress
            }
        }
    }

    # Return the list, return only unique then reduce to orginal limit
    $ReturnList = $IPAddressList | Select-Object -Unique | Select-Object -First $Limit

    Write-Output -InputObject $ReturnList
}




<#
        CF Functions
        ------------
#>
Function Invoke-CFAPI4Request
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Uri]
        $Uri,
       
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [HashTable]
        $Headers,

        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [Object]
        $Body = $null,

        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Method = 'Get'
    )
    
    try
    {
        $JSONResponse = Invoke-RestMethod -Uri $Uri -Headers $Headers -ContentType 'application/json' -Method $Method -ErrorAction Stop -Body $Body
    }
    catch
    {
        Write-Debug -Message 'Error Processing in Invoke-CFAPI4Request'
        $MyError = $_
        if ($null -ne $MyError.Exception.Response)
        { 
            try
            {
                # Recieved an error from the API, lets get it out
                $result = $MyError.Exception.Response.GetResponseStream()
                $reader = New-Object -TypeName System.IO.StreamReader -ArgumentList ($result)
                $responseBody = $reader.ReadToEnd()
                $JSONResponse = $responseBody | ConvertFrom-Json
                
                $CloudFlareErrorCode = $JSONResponse.Errors[0].code
                $CloudFlareMessage = $JSONResponse.Errors[0].message

                # Some errors are just plain unfriendly, so I make them more understandable
                switch ($CloudFlareErrorCode)
                {
                    9103    
                    {
                        throw '[CloudFlare Error 9103] Your Cloudflare API or email address appears to be incorrect.' 
                    }
                    81019   
                    {
                        throw '[CloudFlare Error 81019] Cloudflare access rule quota has been exceeded: You may be trying to add more access rules than your account currently allows. Please check the --rule-limit option.' 
                    }
                    default 
                    {
                        throw '[CloudFlare Error {0}] {1}' -f $CloudFlareErrorCode, $CloudFlareMessage 
                    }
                }
            }
            catch
            {
                # An error has occured whilst processing the error, so we will just throw the original error
                Throw $MyError
            }
        }
        else
        {
            # This wasn't an error from the API, so we need to let the user know directly
            Throw $MyError
        }
    }

    Write-Output -InputObject $JSONResponse
}


function Connect-CFClientAPI
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $APIToken,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $EmailAddress
    )

    # Headers for CloudFlare APIv4
    $Headers = @{
        'X-Auth-Key'   = $APIToken
        'X-Auth-Email' = $EmailAddress
    }

    $Uri = 'https://api.cloudflare.com/client/v4/user'

    try 
    {
        Write-Verbose -Message 'Attempting to connect'
        $null = Invoke-CFAPI4Request -Uri $Uri -Headers $Headers -ErrorAction Stop
        Write-Verbose -Message 'Connected Successfully'

        # Make the headers we used available accross the entire script scope
        $Script:Headers = $Headers
    }
    catch
    {
        $MyError = $_
        Throw $MyError
    }
}


Function Get-CFZoneID
{
    [CmdletBinding()]
    [OutputType([String])]
    Param
    (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Zone
    )

    $Uri = 'https://api.cloudflare.com/client/v4/zones'

    try 
    {
        Write-Verbose -Message 'Getting Zone information'
        $Response = Invoke-CFAPI4Request -Uri $Uri -Headers $Headers -ErrorAction Stop
    }
    catch
    {
        $MyError = $_
        Throw $MyError
    }

    $ZoneData = $Response.Result | Where-Object -FilterScript {
        $_.name -eq $Zone
    }
    
    if ($null -ne $ZoneData)
    {
        $ZoneData.ID
    }
    else
    {
        throw 'Zone not found in CloudFlare'
    }
}


Function Add-CFWhiteListIP
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $IPAddress,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ZoneID
    )
    
    # If we specified a zone earlier, create the access rules there, else, do it at a user level
    if ($ZoneID -ne 0)
    {
        $Data = @{
            'mode'          = 'whitelist'
            'notes'         = 'tor_exit'
            'configuration' = @{
                'value'     = $IPAddress
                'target'    = 'ip'
            }
            'group'         = @{
                'id'        = 'zone'
            }
        }
        $Uri = 'https://api.cloudflare.com/client/v4/zones/{0}/firewall/access_rules/rules' -f $ZoneID
    }
    else
    {
        $Data = @{
            'mode'          = 'whitelist'
            'notes'         = 'tor_exit'
            'configuration' = @{
                'value'     = $IPAddress
                'target'    = 'ip'
            }
            'group'         = @{
                'id'        = 'owner'
            }
        }
        $Uri = 'https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules'
    }

    $JSONData = $Data | ConvertTo-Json

    try 
    {
        Write-Verbose -Message 'Adding IP address as Whitelist'
        $Response = Invoke-CFAPI4Request -Uri $Uri -Headers $Headers -Body $JSONData -Method Post -ErrorAction Stop
    }
    catch
    {
        $MyError = $_
        Throw $MyError
    }
}


Function Remove-CFWhiteListIP
{
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $RuleID,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ZoneID
    )   
    
    # URI will change if we specified a DNS zone or not
    if ($ZoneID -ne 0)
    {
        $Uri = 'https://api.cloudflare.com/client/v4/zones/{0}/firewall/access_rules/rules/{1}' -f $ZoneID, $RuleID
    }
    else
    {
        $Uri = 'https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules/{0}' -f $RuleID
    }

    try 
    {
        Write-Verbose -Message 'Removing IP'
        $Response = Invoke-CFAPI4Request -Uri $Uri -Headers $Headers -Method Delete -ErrorAction Stop
    }
    catch
    {
        $MyError = $_
        Throw $MyError
    }
}


Function Get-CFWhitelist
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ZoneID
    )  
    
    # Get the first page, from there we will be able to see the total page numbers
    try
    {
        $LatestPage = Get-CFWhitelistPage -ZoneID $ZoneID -PageNumber 1 -ErrorAction Stop
        $result = $LatestPage.result
        $TotalPages = $LatestPage.result_info.total_pages
    }
    catch
    {
        $MyError = $_
        throw $MyError
    }

    $PageNumber = 2  
    
    # Get any more pages
    while ($PageNumber -le $TotalPages)
    {
        try
        {
            $LatestPage = Get-CFWhitelistPage -ZoneID $ZoneID -PageNumber $PageNumber -ErrorAction Stop
            $result += $LatestPage.result
            $PageNumber++
        }
        catch
        {
            $MyError = $_
            throw $MyError
            break
        }
    }
        
    $result
}


Function Get-CFWhitelistPage
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]        
        [String]
        $ZoneID,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [int]
        $PageNumber,

        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [int]
        $PageLimit = 50
    )
    
    # Need to send page number and limit as part of request
    $Data = @{
        'page'     = $PageNumber
        'per_page' = $PageLimit
    }
    
    # If we specified a zone earlier, then we call the zone page
    if ($ZoneID -ne 0)
    {
        $Uri = 'https://api.cloudflare.com/client/v4/zones/{0}/firewall/access_rules/rules' -f $ZoneID
    }
    else
    {
        $Uri = 'https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules/'
    }  

    try 
    {
        $Response = Invoke-CFAPI4Request -Uri $Uri -Headers $Headers -Body $Data -ErrorAction Stop
    }
    catch
    {
        $MyError = $_
        Throw $MyError
    }

    Write-Output -InputObject $Response
}




<#
        Main
        ----
#>

# Connect to the CloudFlare Client API
try
{
    Connect-CFClientAPI -APIToken $Token -EmailAddress $Email -ErrorAction Stop
}
catch
{
    throw $_
}

# Determine Zone/Domain information if a zone is specified
$ZoneID = 0
if ($Zone -eq '')
{
    'No zone specified. Whitelist will be applied accross all domains.'
}
else
{
    try 
    {
        'Selected Zone {0}' -f $Zone
        $ZoneID = Get-CFZoneID -Zone $Zone -ErrorAction Stop
        Write-Verbose -Message ('Zone id is {0}' -f $ZoneID)
    } 
    catch 
    {
        $MyError = $_
        throw $MyError
    }
}

# Extract currently active Tor whitelist
try
{
    $Rules = Get-CFWhitelist -ZoneID $ZoneID -ErrorAction Stop
} 
catch 
{
    $MyError = $_
    throw $MyError
}

$TotalRules = ($Rules | Measure-Object).Count
Write-Verbose -Message ('Found {0} access rules' -f $TotalRules)

# Select just the TOR specific rules
$Tor_ExitRules = $Rules | Where-Object -FilterScript {
    $_.notes -eq 'tor_exit'
}

$TotalTor_ExitRules = ($Tor_ExitRules | Measure-Object).Count
'Found {0} matching Tor access rules' -f $TotalTor_ExitRules

# Remove all the active Tor rules if --clear-rules is specified
if ($ClearRules)
{
    Write-Verbose -Message 'Clearing all active Tor Rules'
    $Count = 0
    foreach ($Rule in $Tor_ExitRules)
    { 
        $Count++
        $RuleID = $Rule.id
        $IPAddress = $Rule.Configuration.Value
        Write-Verbose -Message ('Removing access rule for IP {0}' -f $IPAddress)
        try
        {
            Remove-CFWhiteListIP -RuleID $RuleID -ZoneID $ZoneID -ErrorAction Stop
        } 
        catch 
        {
            $MyError = $_
            Write-Error -Exception $MyError
        }      
        
        $PercentComplete = $Count / $TotalTor_ExitRules * 100
        Write-Progress -Activity 'Removing Tor Exit Nodes' -Status ('{0:f2}% Complete' -f $PercentComplete) -PercentComplete $PercentComplete
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity 'Removing Tor Exit Nodes' -Status 'Completed' -Completed
    'Removed {0} matching Tor access rules' -f $Count
    'All Tor access rules have been removed'
}
else
{
    Write-Verbose -Message 'Updating Tor rules'
    
    # Calculate the max number of Tor rules that we can insert.
    $MaxTorRules = $RuleLimit - ($TotalRules - $TotalTor_ExitRules)
    Write-Verbose -Message ('Can Create a maximum of {0} access rules' -f $MaxTorRules)

    # Retrieve list of top Tor exits
    try
    {
        $TorExitNodes = Get-TopTorExitNodeIPAddress -Limit $MaxTorRules -ErrorAction Stop
    }
    catch
    {
        $MyError = $_
        Write-Error -Exception $MyError
    }

    $TotalExitNodes = ($TorExitNodes | Measure-Object).Count

    # did we get the right number of exit nodes
    if ($TotalExitNodes -ne 0)
    {
        'Retrieved {0} exit IP addresses from Onionoo' -f $TotalExitNodes
    } 
    else
    {
        throw 'Did not retrieve any Tor exit IPs from Onionoo'
    }

    # Determine the rules we need to remove, these are exit nodes which no longer appear in Onionoo
    $RulesToRemove = $Tor_ExitRules | Where-Object -FilterScript {
        $_.configuration.value -notin $TorExitNodes
    }
    'There are {0} old rules that need to be removed' -f (($RulesToRemove | Measure-Object).Count)

    foreach ($Rule in $RulesToRemove)
    { 
        $RuleID = $Rule.id
        $IPAddress = $Rule.Configuration.Value
        Write-Verbose -Message ('Removing access rule for IP {0}' -f $IPAddress)
        try
        {
            Remove-CFWhiteListIP -RuleID $RuleID -ZoneID $ZoneID -ErrorAction Stop
        }
        catch
        {
            $MyError = $_
            Write-Error -Exception $MyError
        } 
        $PercentComplete = $Count / $TotalTor_ExitRules * 100
        Write-Progress -Activity 'Removing Tor Exit Nodes' -Status ('{0:f2}% Complete' -f $PercentComplete) -PercentComplete $PercentComplete
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity 'Removing Tor Exit Nodes' -Status 'Completed' -Completed

    # Get the current IP addresses in CF
    $CurrentWhitelistedIPS = $Tor_ExitRules | ForEach-Object -Process {
        $_.configuration.value
    }

    # Filter out any addresses from OO which are not in CF
    $IPAddressesToAdd = $TorExitNodes | Where-Object -FilterScript {
        $_ -notin $CurrentWhitelistedIPS
    }
    
    $NumberOfRulesToAdd = ($IPAddressesToAdd | Measure-Object).Count
    'There are {0} new rules to be added' -f $NumberOfRulesToAdd

    $TotalCount   = 0
    $SuccessCount = 0
    $ErrorCount   = 0
    foreach ($IPAddress in $IPAddressesToAdd)
    { 
        $TotalCount++ 
        $PercentComplete = $TotalCount / $NumberOfRulesToAdd * 100
        Write-Progress -Activity 'Adding Tor Exit Nodes' -Status ('{0:f2}% Complete' -f $PercentComplete) -PercentComplete $PercentComplete
        Write-Verbose -Message ('Adding access rules for IP {0}' -f $IPAddress)
        try
        {
            Add-CFWhiteListIP -IPAddress $IPAddress -ZoneID $ZoneID
            Start-Sleep -Seconds 1
            $SuccessCount++
        }
        catch
        {
            $ErrorCount++
            $MyError = $_
            Write-Error -Exception $MyError
        }        
    }
    Write-Progress -Activity 'Removing Tor Exit Nodes' -Status 'Completed' -Completed
    
    'Done! Added {0} new rules, {1} failed. There (should) now be {2} Tor Exit relay rules' -f $SuccessCount, $ErrorCount, $MaxTorRules
}
