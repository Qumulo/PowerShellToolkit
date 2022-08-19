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
function Get-QQFSStatistics {
<#
    .SYNOPSIS
        Retrieve general file system statistics.
    .DESCRIPTION
        Retrieve general file system statistics.
    .EXAMPLE
        Get-QQFileSystemStatistics [-Json]
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
		$url = "/v1/file-system"

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

function Get-QQFSPermissionSettings {
<#
	.SYNOPSIS
		Get permissions settings.
	.DESCRIPTION
		Get permissions settings.
	.EXAMPLE
		Get-QQFSPermissionSettings [-Json]
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
		$url = "/v1/file-system/settings/permissions"

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

function Set-QQFSPermissionSettings {
<#
	.SYNOPSIS
		Set permissions settings.
	.DESCRIPTION
		Set permissions settings.
	.EXAMPLE
		Set-QQFSPermissionSettings [-Cross_Protocol|-Native][-Json]
	#>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "CrossProtocol")][switch]$CrossProtocol,
		[Parameter(Mandatory = $True,ParameterSetName = "Native")][switch]$Native,
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
		$url = "/v1/file-system/settings/permissions"

		# API body definition
		if($CrossProtocol){
			$body = @{ mode = "CROSS_PROTOCOL"}
		}
		elseif($Native){
			$body = @{ mode = "NATIVE"}
		}

		# API call ru
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'PUT' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

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
	
function Get-QQFSAtimeSettings {
<#
	.SYNOPSIS
		Get access time (atime) settings.
	.DESCRIPTION
		Get access time (atime) settings.
	.EXAMPLE
		Get-QQFSAtimeSettings [-Json]
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
		$url = "/v1/file-system/settings/atime"

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

function Set-QQFSAtimeSettings {
<#
	.SYNOPSIS
		Set access time (atime) settings.
	.DESCRIPTION
		Set access time (atime) settings.
	.PARAMETER Enable
		Enable access time (atime) updates.
	.PARAMETER Disable
		Disable access time (atime) updates.
	.PARAMETER Granularity [HOUR|DAY|WEEK]
		Specify granularity for access time (atime) updates.
	.EXAMPLE
		Set-QQFSAtimeSettings [-Enable][-Json]
		Set-QQFSAtimeSettings [-Disable][-Json]
		Set-QQFSAtimeSettings [-Granularity][HOUR|DAY|WEEK][-Json]
	#>

	[CmdletBinding(DefaultParametersetName='None')]
	param(
		[Parameter(Mandatory = $False, ParameterSetName = "Enable")][switch]$Enable,
		[Parameter(Mandatory = $False, ParameterSetName = "Disable")][switch]$Disable,
		[Parameter(Mandatory = $False)][ValidateSet("Hour","Day","Week")][string]$Granularity,
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
		$url = "/v1/file-system/settings/atime"

		# API body definition
		$body = @{}
		if($Enable){
			$body += @{ enabled = $True }
		}
		elseif($Disable){
			$body += @{ enabled = $False }
		}
		if($Granularity){
			$body += @{ granularity = $Granularity.ToUpper() }
		}

		# API call ru
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