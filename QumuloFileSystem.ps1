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
		[Parameter(Mandatory = $True,ParameterSetName = "CrossProtocol")] [switch]$CrossProtocol,
		[Parameter(Mandatory = $True,ParameterSetName = "Native")] [switch]$Native,
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
		$url = "/v1/file-system/settings/permissions"

		# API body definition
		if ($CrossProtocol) {
			$body = @{ Mode = "CROSS_PROTOCOL" }
		}
		elseif ($Native) {
			$body = @{ Mode = "NATIVE" }
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

	[CmdletBinding(DefaultParameterSetName = 'None')]
	param(
		[Parameter(Mandatory = $False,ParameterSetName = "Enable")] [switch]$Enable,
		[Parameter(Mandatory = $False,ParameterSetName = "Disable")] [switch]$Disable,
		[Parameter(Mandatory = $False)][ValidateSet("Hour","Day","Week")] [string]$Granularity,
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
		$url = "/v1/file-system/settings/atime"

		# API body definition
		$body = @{}
		if ($Enable) {
			$body += @{ enabled = $True }
		}
		elseif ($Disable) {
			$body += @{ enabled = $False }
		}
		if ($Granularity) {
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


function Get-QQFSNotifySettings {
<#
	.SYNOPSIS
		Get FS notify settings.
	.DESCRIPTION
		Get FS notify related settings.
	.EXAMPLE
		Get-QQFSNotifySettings [-Json]
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
		$url = "/v1/file-system/settings/notify"

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

function Set-QQFSNotifySettings {
<#
	.SYNOPSIS
		Set FS notify settings
	.DESCRIPTION
		Set FS notify related settings.
	.PARAMETER RecursiveMode [ENABLED, DISABLED_ERROR,DISABLED_IGNORE]
		Notify recursive mode to set (ENABLED, DISABLED_ERROR,DISABLED_IGNORE)
		Set FS notify settings
		Change global FS settings for notify and change watch.

		There is one setting for recursive mode. The use of recursive mode may have
		performance impact for some workloads, so be default, recursive change watches
		are disabled. These are the available modes:

		DISABLED_ERROR
		Recursive change notify requests will immediately return an error. This is
		the default setting as it avoids the performance impact of recursive
		notifications while clearly presenting errors when applications try to
		initiate a recursive watch.

		DISABLED_IGNORE
		Recursive change notify requests will be accepted, but notifications will
		only be sent for the top level directory being watched. In other words, it
		will behave as if the recursive flag was not provided. This setting can be
		used to improve compatibility with applications that request recursion but
		don't actually depend on it. For some applications, however, this can cause
		hangs or other unexpected behavior when recursion is needed in order to
		function properly.

		ENABLED
		Real recursive change notify support. Notifications for all descendants of
		the watched directory will be pushed to the watcher. It can be quite
		expensive in term of performance. For example, consider that a watch on the
		root of the file system will receive a notification for every single change
		on the entire cluster.

	.EXAMPLE
		Set-QQFSNotifySettings RecursiveMode [ENABLED, DISABLED_ERROR,DISABLED_IGNORE][-Json]
	#>

	[CmdletBinding(DefaultParameterSetName = 'None')]
	param(
		[Parameter(Mandatory = $True)][ValidateSet("ENABLED","DISABLED_ERROR","DISABLED_IGNORE")] [string]$RecursiveMode,
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
		$url = "/v1/file-system/settings/notify"

		# API body definition
		$body = @{
			'recursive_mode' = $RecursiveMode.ToUpper()
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
