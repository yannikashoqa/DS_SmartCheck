# DS_SmartCheck
Deep Security SmartCheck Scripts

AUTHOR		: Yanni Kashoqa

TITLE		: Deep Security SmartCheck Automation Scripts

DESCRIPTION	: These Powershell scripts will perform automation tasks against Deep Security SmartCheck

FEATURES
The ability to perform the following:-
- Get-ScanResults: Retreived the scan results based on a Scan Task ID

REQUIRMENTS
- Supports Deep Security as a Service
- PowerShell 6.x or 7.x
- Login Credentials to the Deep Security SmartCheck console
- Create a DS-Config.json in the same folder with the following content:
~~~~JSON
{
    "MANAGER": "",
    "PORT": "443",
    "USER_NAME": "",
    "PASSWORD": "",
    "SCAN_ID": ""
}
~~~~

MANAGER: IP or FQDN of the DSSC server

PORT: DSSC Port.  Usually 443

USER_NAME: DSSC User Name

PASSWORD: DSSC Password

SCAN_ID: Scan ID from the DSSC console
