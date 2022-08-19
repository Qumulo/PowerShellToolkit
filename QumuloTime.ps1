<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloTime.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo date and time configurations and operations
	-------------------------------------------------------------------------
    MIT License

    Copyright (c) 2022 Qumulo, Inc.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
	===========================================================================
#>
function Get-QQTime {
<#
    .SYNOPSIS
        Get time configuration.
    .DESCRIPTION
        Retrieve the server's time-management configuration. Refer to the 'Set Time Configuration' method for a description of the returned fields.
    .EXAMPLE
        Get-QQTime [-Json]
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)][switch]$Json
	)
	if ($SkipCertificateCheck -eq 'true') {
		$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
	}

	try {
        # Existing BearerToken check
		if (!$global:Credentials) {
			Login-QQCluster
		}
		else {
			if (!$global:Credentials.BearerToken.StartsWith("session-v1")) {
				Login-QQCluster
			}
		}

		$bearerToken = $global:Credentials.BearerToken
		$clusterName = $global:Credentials.ClusterName
		$portNumber = $global:Credentials.PortNumber

		$TokenHeader = @{
			Authorization = "Bearer $bearerToken"
		}

        # API url definition
		$url = "/v1/time/settings"

        # API call ru
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

            # Response
			if ($Json) {
				return @($response) | ConvertTo-Json -Depth 10
			}
			else {
				return $response
			}
		}
		catch {
			$_.Exception.Response
		}
	}
	catch {
		$_.Exception.Response
	}
}

function Get-QQTimeStatus {
<#
    .SYNOPSIS
        Get time configuration status.
    .DESCRIPTION
        Retrieve the time status of the underlying system
    .EXAMPLE
        Get-QQTimeStatus [-Json]
    #>
    
    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json
    )
    if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
    }

    try {
        # Existing BearerToken check
        if (!$global:Credentials) {
            Login-QQCluster
        }
        else {
            if (!$global:Credentials.BearerToken.StartsWith("session-v1")) {
                Login-QQCluster
            }
        }

        $bearerToken = $global:Credentials.BearerToken
        $clusterName = $global:Credentials.ClusterName
        $portNumber = $global:Credentials.PortNumber

        $TokenHeader = @{
            Authorization = "Bearer $bearerToken"
        }

        # API url definition
        $url = "/v1/time/status"

        # API call run
        try {
            $response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

            # Response
            if ($Json) {
                return @($response) | ConvertTo-Json -Depth 10
            }
            else {
                return $response
            }
        }
        catch {
            $_.Exception.Response
        }
    }
    catch {
        $_.Exception.Response
    }
}

function Set-QQTime {
    <#
        .SYNOPSIS
            Set time configuration.
        .DESCRIPTION
            Set the server's time-management configuration.
        .PARAMETER UsedAD $True|$False
            Whether to use the Active Directory controller as the primary NTP server
        .PARAMETER NtpServers NTP_SERVERS
            List of NTP servers
        .EXAMPLE
            Set-QQTime -UseAD  $True|$False  [-Json]
  
             Set-QQTime -NtpServers NTP_SERVERS [-Json]
        #>

        # CmdletBinding parameters
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $False)][switch]$Json,
            [Parameter(Mandatory = $False)][bool]$UsedAD,
            [Parameter(Mandatory = $False)][array]$NtpServers
        )
        if ($SkipCertificateCheck -eq 'true') {
            $PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
        }
    
        try {
            # Existing BearerToken check
            if (!$global:Credentials) {
                Login-QQCluster
            }
            else {
                if (!$global:Credentials.BearerToken.StartsWith("session-v1")) {
                    Login-QQCluster
                }
            }
    
            $bearerToken = $global:Credentials.BearerToken
            $clusterName = $global:Credentials.ClusterName
            $portNumber = $global:Credentials.PortNumber
    
            $TokenHeader = @{
                Authorization = "Bearer $bearerToken"
            }
    
            # API Request Body
            $body = @{}
    
            if($UsedAD -eq $true){$body += @{"use_ad_for_primary" = $true}}
            else{$body += @{"use_ad_for_primary" = $false}}
            if($NtpServers){$body += @{"ntp_servers" = $NtpServers}}

            Write-Debug($body| ConvertTo-Json -Depth 10)
    
            # API url definition
            $url = "/v1/time/settings"

            # API call run
            try {
                $response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
    
                # Response
                if ($Json) {
                    return @($response) | ConvertTo-Json -Depth 10
                }
                else {
                    return $response
                }
            }
            catch {
                $_.Exception.Response
            }
        }
        catch {
            $_.Exception.Response
        }
    }

function List-QQTimeZones {
<#
    .SYNOPSIS
        List timezones supported by Qumulo
    .DESCRIPTION
        Get a list of all timezones supported by Qumulo Core
    .EXAMPLE
        List-QQTimeZone [-Json]
    #>

    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json
    )
    if ($SkipCertificateCheck -eq 'true') {
        $PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
    }

    try {
        # Existing BearerToken check
        if (!$global:Credentials) {
            Login-QQCluster
        }
        else {
            if (!$global:Credentials.BearerToken.StartsWith("session-v1")) {
                Login-QQCluster
            }
        }

        $bearerToken = $global:Credentials.BearerToken
        $clusterName = $global:Credentials.ClusterName
        $portNumber = $global:Credentials.PortNumber

        $TokenHeader = @{
            Authorization = "Bearer $bearerToken"
        }

        # API url definition
        $url = "/v1/time/timezones"

        # API call run	
        try {
            $response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

            # Response
            if ($Json) {
                return @($response) | ConvertTo-Json -Depth 10
            }
            else {
                return $response
            }
        }
        catch {
            $_.Exception.Response
        }
    }
    catch {
        $_.Exception.Response
    }
}
