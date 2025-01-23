<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloAudit.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo Audit log configurations and operations
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
function Get-QQSyslogConfig {
<#
    .SYNOPSIS
        Get audit syslog server configuration
    .DESCRIPTION
        Retrieves audit log syslog configuration for the cluster.
    .EXAMPLE
        Get-QQSyslogConfig [-Json]
    .LINK
        https://care.qumulo.com/hc/en-us/articles/360021454193-Qumulo-Core-Audit-Logging
    #>

	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json
	)
	if ($SkipCertificateCheck -eq 'true') {
		$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
	}

	# Existing BearerToken check
	try {
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
		$url = "/v1/audit/syslog/config"

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Response
			if ($json) {
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

function Get-QQSyslogStatus {
<#
    .SYNOPSIS
        Get audit syslog server status
    .DESCRIPTION
        Retrieves the syslog connection status of audit log.
    .EXAMPLE
        Get-QQSyslogStatus [-Json]
    .LINK
        https://care.qumulo.com/hc/en-us/articles/360021454193-Qumulo-Core-Audit-Logging#details-0-2
    #>

	# CmdletBinding parameters. 
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)]
		[switch]$json
	)
	if ($SkipCertificateCheck -eq 'true') {
		$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
	}

	# Existing BearerToken check
	try {
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
		$url = "/v1/audit/syslog/status"

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Response
			if ($json) {
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

function Set-QQSyslogConfig {
<#
    .SYNOPSIS
        Set audit syslog server configuration
    .DESCRIPTION
        Modifies audit log syslog configuration for the cluster.
    .PARAMETER Enable $true|$false
        Enable or Disable audit log.
    .PARAMETER ServerAddress SERVER_ADDRESS
        The IP address, hostname, or fully qualified domain name of your remote syslog server.
    .PARAMETER ServerPort SERVER_PORT
        The port to connect to on your remote syslog server.
    .EXAMPLE
        Set-QQSyslogConfig [-Json]
            -Enable     Enable or Disable audit log.
            -ServerAddress SERVER_ADDRESS
            -ServerPort SERVER_PORT
    .LINK
        https://care.qumulo.com/hc/en-us/articles/360021454193-Qumulo-Core-Audit-Logging#details-0-2
    #>

	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$json,
		[Parameter(Mandatory = $False)] [bool]$Enable,
		[Parameter(Mandatory = $False)] [int32]$ServerPort,
		[Parameter(Mandatory = $False)]
		# Valid FQDN or IP address check
		[ValidateScript({
				if ($_ -as [ipaddress]) {
					$True
				}
				else {
					try {
						[System.Net.Dns]::GetHostEntry($_)
					}
					catch {
						throw "$_ is not a valid IP or hostname. Try again."
					}
				}
				###
			})] [string]$ServerAddress
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

		# API Request Body
		$body = @{}

		if ($Enable -eq $true) { $body += @{ "enabled" = $true } }
		else { $body += @{ "enabled" = $false } }
		if ($ServerAddress) { $body += @{ "server_address" = $ServerAddress } }
		if ($ServerPort) { $body += @{ "server_port" = $ServerPort } }

		Write-Debug ($body | ConvertTo-Json -Depth 10)

		# API url definition
		$url = "/v1/audit/syslog/config"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

			# Response
			if ($json) {
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

function Get-QQCloudWatchConfig {
<#
    .SYNOPSIS
        Get audit CloudWatch configuration
    .DESCRIPTION
        Retrieves audit log CloudWatch configuration for the cluster.
    .EXAMPLE
        Get-QQCloudWatchConfig [-Json]
    .LINK
        https://care.qumulo.com/hc/en-us/articles/360048158293-Qumulo-in-AWS-Audit-Logging-with-CloudWatch#requirements-0-1
    #>

	# CmdletBinding parameters. 
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)]
		[switch]$json
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
		$url = "/v1/audit/cloudwatch/config"

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Response
			if ($json) {
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

function Get-QQCloudWatchStatus {
<#
    .SYNOPSIS
        Get audit CloudWatch status
    .DESCRIPTION
        Retrieves audit log CloudWatch status for the cluster.
    .EXAMPLE
        Get-QQCloudWatchStatus [-Json]
    .LINK
        https://care.qumulo.com/hc/en-us/articles/360048158293-Qumulo-in-AWS-Audit-Logging-with-CloudWatch#requirements-0-1
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)]
		[switch]$json
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
		$url = "/v1/audit/cloudwatch/status"
		try {
			# API call run	
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Response
			if ($json) {
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

function Set-QQCloudWatchConfig {
<#
    .SYNOPSIS
        Set audit CloudWatch configuration
    .DESCRIPTION
        Modifies audit log CloudWatch configuration for the cluster.
    .PARAMETER Enable $true|$false
        Enable or Disable audit log.
    .PARAMETER LogGroupName LOG_GROUP_NAME
        The group name in CloudWatch Logs to send logs to.
    .PARAMETER Region REGION
        The port to connect to on your remote syslog server.
    .EXAMPLE
        Set-QQCloudWatchConfig [-Json]
            -Enable  $true|$false
            -LogGroupName LOG_GROUP_NAME
            -Region REGION
    .LINK
        https://care.qumulo.com/hc/en-us/articles/360048158293-Qumulo-in-AWS-Audit-Logging-with-CloudWatch#requirements-0-
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$json,
		[Parameter(Mandatory = $False)] [bool]$Enable,
		[Parameter(Mandatory = $False)] [string]$LogGroupName,
		[Parameter(Mandatory = $False)] [string]$Region
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
		# API Request Body
		$body = @{}

		if ($Enable -eq $true) { $body += @{ "enabled" = $true } }
		else { $body += @{ "enabled" = $false } }
		if ($LogGroupName) { $body += @{ "log_group_name" = $LogGroupName } }
		if ($Region) { $body += @{ "region" = $Region } }

		Write-Debug ($body | ConvertTo-Json -Depth 10)

		# API url definition
		$url = "/v1/audit/cloudwatch/config"

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

			# Response
			if ($json) {
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
