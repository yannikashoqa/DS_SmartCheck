Clear-Host
$ErrorActionPreference = 'Continue'

$Config     = (Get-Content "$PSScriptRoot\DS-Config.json" -Raw) | ConvertFrom-Json
$Manager    = $Config.MANAGER
$Port       = $Config.PORT
$UserName   = $Config.USER_NAME
$Password   = $Config.PASSWORD
$SCAN_ID    = $Config.SCAN_ID

$StartTime  = $(get-date)

$DSSC_URI = "https://" + $Manager + ":" + $Port
$SCAN_URI = $DSSC_URI + '/api/scans/' + $SCAN_ID
$AUTH_URI = $DSSC_URI + '/api/sessions'

$AuthHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$AuthHeaders.Add("Content-Type", "application/json")
$AuthHeaders.Add("X-Api-Version", '2018-05-01')

$creds = @{
    user = @{
        userID = $UserName
        password = $Password
        }
}
$AuthData = $creds | ConvertTo-Json -Compress |  ForEach-Object{$_.replace('"', '\"')}
$Session_Data = curl --insecure --location --request POST $AUTH_URI --header 'Content-Type: application/json' --header 'X-Api-Version: 2018-05-01'  -d $AuthData
$Session_Data_json = $Session_Data | ConvertFrom-Json
$SessionID      = $Session_Data_json.id
$SessionToken   = $Session_Data_json.token
$Bearer_Token = "Bearer " + $SessionToken

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", $Bearer_Token)
$headers.Add("X-Api-Version", '2018-05-01')

$Scan_Results = Invoke-RestMethod -Uri $SCAN_URI -Method 'GET' -Headers $headers -SkipCertificateCheck

#Sample code for Vulnerability Structure
#$VulnerabilityURI = $SCAN_URI + "/layers/sha256:28252775b2955bcd1a204d2cb81e5b3696533ecf85bd50cd2edb78780d4da686/vulnerabilities"
#$resultsVuln = Invoke-RestMethod -Uri $VulnerabilityURI -Method 'GET' -Headers $headers -SkipCertificateCheck
#$resultsVuln.vulnerabilities[0].name
#$resultsVuln.vulnerabilities[0].version
#$resultsVuln.vulnerabilities[0].vulnerabilities
#$resultsVuln.vulnerabilities[0].vulnerabilities[0].name
#$resultsVuln.vulnerabilities[0].vulnerabilities[0].severity

# Iterate through Layer IDs to check for results.
foreach ($Item in $Scan_Results.details.results){
    $LayerID = $Item.id
    write-host "Layer ID: " $LayerID    
    $VulnerabilityURI = $SCAN_URI + "/layers/" + $LayerID + "/vulnerabilities"
    $resultsVuln = Invoke-RestMethod -Uri $VulnerabilityURI -Method 'GET' -Headers $headers -SkipCertificateCheck

    $MalwareURI = $SCAN_URI + "/layers/" + $LayerID + "/malware"
    $resultsMal = Invoke-RestMethod -Uri $MalwareURI -Method 'GET' -Headers $headers -SkipCertificateCheck

    $ContentURI = $SCAN_URI + "/layers/" + $LayerID + "/contents"
    $resultsCont = Invoke-RestMethod -Uri $ContentURI -Method 'GET' -Headers $headers -SkipCertificateCheck
    
    if ($resultsVuln.vulnerabilities.Count -ge 1) {
        #Write-Output $resultsVuln | ConvertTo-Json
        ForEach ($Vuln_App in $resultsVuln.vulnerabilities){
            Write-host $Vuln_App.name $Vuln_App.version
            ForEach ($Vuln_CVE in $Vuln_App.vulnerabilities){
                Write-host $Vuln_CVE.name  $Vuln_CVE.severity
            }
        }
    }

    if ($resultsMal.malware.Count -ge 1) {
        Write-Output $resultsMal | ConvertTo-Json
    }

    if ($resultsCont.contents.Count -ge 1) {
        Write-Output $resultsCont | ConvertTo-Json
    }
}



#Delete Session
$DelHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$DelHeaders.Add("Content-Type", "application/json")
$DelHeaders.Add("X-Api-Version", '2018-05-01')
$DelHeaders.Add("Authorization", $Bearer_Token)
$DEL_URI = $AUTH_URI + "/" + $SessionID
Invoke-RestMethod -Uri $DEL_URI -Method 'DELETE' -Headers $DelHeaders -SkipCertificateCheck

$elapsedTime = $(get-date) - $StartTime
$totalTime = "{0:HH:mm:ss}" -f ([datetime]$elapsedTime.Ticks)
Write-Host "Script Execution is Complete.  It took $totalTime"