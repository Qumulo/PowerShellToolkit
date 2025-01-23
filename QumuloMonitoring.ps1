<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloMonitoring.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo cloud-based monitoring and remote support configurations and operations
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
function Get-QQMonitoringConfig {
<#
    .SYNOPSIS
        Get monitoring configuration.
    .DESCRIPTION
       Get monitoring configuration.
    .EXAMPLE
        Get-QQMonitoringConfig [-Json]
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json
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
			if (!($global:Credentials.BearerToken -match "^(session-v1|access-v1)")) {
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
		$url = "/v1/support/settings"

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

function List-QQMonitoringStatus {
<#
    .SYNOPSIS
        List the monitoring status of all nodes: whether various kinds of monitoring connections are enabled/connected/etc.
    .DESCRIPTION
        List the monitoring status of all nodes: whether various kinds of monitoring connections are enabled/connected/etc.
    .EXAMPLE
        List-QQMonitoringStatus  [-Json]
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json
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
			if (!($global:Credentials.BearerToken -match "^(session-v1|access-v1)")) {
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
		$url = "/v1/support/status/"

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

# function Set-QQTime {
# <#
#     .SYNOPSIS
#         Set time configuration.
#     .DESCRIPTION
#         Set the server's time-management configuration.
#     .PARAMETER UsedAD $True|$False
#         Whether to use the Active Directory controller as the primary NTP server
#     .PARAMETER NtpServers NTP_SERVERS
#         List of NTP servers
#     .EXAMPLE
#         Set-QQTime -UseAD  $True|$False  [-Json]

#             Set-QQTime -NtpServers NTP_SERVERS [-Json]
#     #>

#     # CmdletBinding parameters
#     [CmdletBinding()]
#     param(
#         [Parameter(Mandatory = $False)][switch]$Json,
#         [Parameter(Mandatory = $False)][bool]$UsedAD,
#         [Parameter(Mandatory = $False)][array]$NtpServers
#     )
#     if ($SkipCertificateCheck -eq 'true') {
#         $PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
#     }

#     try {
#         # Existing BearerToken check
#         if (!$global:Credentials) {
#             Login-QQCluster
#         }
#         else {
#             if (!($global:Credentials.BearerToken -match "^(session-v1|access-v1)")) {
#                 Login-QQCluster
#             }
#         }

#         $bearerToken = $global:Credentials.BearerToken
#         $clusterName = $global:Credentials.ClusterName
#         $portNumber = $global:Credentials.PortNumber

#         $TokenHeader = @{
#             Authorization = "Bearer $bearerToken"
#         }

#         # API Request Body
#         $body = @{}

#         if($UsedAD -eq $true){$body += @{"use_ad_for_primary" = $true}}
#         else{$body += @{"use_ad_for_primary" = $false}}
#         if($NtpServers){$body += @{"ntp_servers" = $NtpServers}}

#         Write-Debug($body| ConvertTo-Json -Depth 10)

#         # API url definition
#         $url = "/v1/time/settings"

#         # API call run
#         try {
#             $response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

#             # Response
#             if ($Json) {
#                 return @($response) | ConvertTo-Json -Depth 10
#             }
#             else {
#                 return $response
#             }
#         }
#         catch {
#             $_.Exception.Response
#         }
#     }
#     catch {
#         $_.Exception.Response
#     }
# }

function Get-QQVPNKeys {
<#
    .SYNOPSIS
       Get VPN keys.
    .DESCRIPTION
        Get VPN keys.
    .EXAMPLE
        Get-QQVPNKeys  [-Json]
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json
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
			if (!($global:Credentials.BearerToken -match "^(session-v1|access-v1)")) {
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
		$url = "/v1/support/vpn-keys"

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


function Get-QQMetrics {
<#
    .SYNOPSIS
        Get all system metrics.
    .DESCRIPTION
        Get all metrics for the cluster.
    .EXAMPLE
        Get-QQMetrics
    #>

	if ($SkipCertificateCheck -eq 'true') {
		$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
	}

	try {
		# Existing BearerToken check
		if (!$global:Credentials) {
			Login-QQCluster
		}
		else {
			if (!($global:Credentials.BearerToken -match "^(session-v1|access-v1)")) {
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
		$url = "/v2/metrics/endpoints/default/data"

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
