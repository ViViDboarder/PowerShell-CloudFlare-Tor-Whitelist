# PowerShell-CloudFlare-Tor-Whitelist
PowerShell script to white-list Tor exit IP addresses in CloudFlare. This allows Tor users to access your websites without CAPTCHA requests

## Thanks
Many thanks to Donncha O'Cearbhaill for the development of his Cloudflare-tor-whitelister. Please visit: https://github.com/DonnchaC/cloudflare-tor-whitelister. Without his work, this would not have been as achievable.

## Description
CloudFlare creates a pretty poor user experience for Tor users. The issue stems from how CloudFlare protect websites from attacks. When users visit a protected website, CloudFlare assigns a threat or risk score to their IP. If an IP is safe, then the user gets to see your page. If an IP is suspicious, then the user will need to complete a CAPTCHA, or in serious cases, denied access.

Due to the high use of Tor for malicious activity, CloudFlare will be suspicious of known Tor exit nodes. This suspicion results in Tor users experiencing repeated CAPTCHA requests. With CloudFlare's popularity, Tor users experience these requests more and more.

The aim of this script is to provide website operators with a way to white-list Tor exit IP addresses. This script is adapted from Donncha O'Cearbhaill's CloudFlare-Tor-Whitelister, whitelist.py.

## Examples
::
	c:> Set-CloudFlareWhitelist.ps1 -Token $MyCloudFlareToken -Email $MyEmail
	
Creates/updates rules for Tor Exit address accross all of your domains in CloudFlare

::
	c:> Set-CloudFlareWhitelist.ps1 -Token $MyCloudFlareToken -Email $MyEmail -Zone contoso.com
	
Creates/updates rules for Tor Exit IP addresses only for the domain contoso.com

::

	c:>Set-CloudFlareWhitelist.ps1 -Token $MyCloudFlareToken -Email $MyEmail -ClearRules
	
Remove all Tor Exit IP address rules specified for all of your domains in CloudFlare
		
## See Also
http://poshsecurity.com
https://github.com/DonnchaC/cloudflare-tor-whitelister
