# PowerShell-CloudFlare-Tor-Whitelist
PowerShell script to white-list Tor exit IP addresses in CloudFlare. This allows Tor users to access your websites without CAPTCHA requests

## Update
You can now control Tor access from the CloudFlare console - https://support.cloudflare.com/hc/en-us/articles/203306930-Does-CloudFlare-block-Tor-

## Thanks
Many thanks to Donncha O'Cearbhaill for the development of his Cloudflare-tor-whitelister. Please visit: https://github.com/DonnchaC/cloudflare-tor-whitelister. Without his work, this would not have been as achievable.

## Description
CloudFlare creates a pretty poor user experience for Tor users, due to how it protects websites from attack. CloudFlare assigns a threat (or risk score) to each users IP address. If the IP address is deemed to be safe, then the user will see your website; if they are deemed suspicious, then the user will need to complete a CAPTCHA or in more serious cases, they are denied access.

Due to the high use of Tor for malicious activity, CloudFlare will always be suspicious of known Tor exit nodes resulting in Tor users experiencing a CAPTCHA request for each CloudFlare protected site that they view. With CloudFlare's popularity, Tor users experience these requests more and more.

The aim of this script is to provide website operators with a way to white-list Tor exit IP addresses. This script is adapted from Donncha O'Cearbhaill's CloudFlare-Tor-Whitelister, whitelist.py.

## Examples
```
c:>.\Set-CloudFlareWhitelist.ps1 -Token $MyCloudFlareToken -Email $MyEmail
```
Creates/updates rules for Tor Exit address accross all of your domains in CloudFlare

```
c:>.\Set-CloudFlareWhitelist.ps1 -Token $MyCloudFlareToken -Email $MyEmail -Zone contoso.com
```
Creates/updates rules for Tor Exit IP addresses only for the domain contoso.com

```
c:>.\Set-CloudFlareWhitelist.ps1 -Token $MyCloudFlareToken -Email $MyEmail -ClearRules
```
Remove all Tor Exit IP address rules specified for all of your domains in CloudFlare
		
## See Also
http://poshsecurity.com
https://github.com/DonnchaC/cloudflare-tor-whitelister
