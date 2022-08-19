<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloQuota.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo directory quota configurations and operations
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
function List-QQDirQuotas {
<#
    .SYNOPSIS
        List all directory quotas
    .DESCRIPTION
        List all directory quotas
    .EXAMPLE
    	List-DirQuotas [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115009394288-Quotas-in-Qumulo-Core
    #>

	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()] [string]$PageSize,
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
		if ($pageSize) {
			$url = "/v1/files/quotas/status/?limit=$pageSize"
		}
		else {
			$url = "/v1/files/quotas/status/"
		}

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Response
			if ($Json) {
				return @($response.quotas) | ConvertTo-Json -Depth 10
			}
			else {
				return $response.quotas
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

function Get-QQDirQuota {
<#
    .SYNOPSIS
        Get a directory quota
    .DESCRIPTION
        Get the directory quota for a directory, its limit in bytes, and current capacity usage.
	.PARAMETER Id [File ID]
		Directory ID
	.PARAMETER Path [Directory Path]
		Directory path
    .EXAMPLE
        Get-QQDirQuota -Id [File ID] [-Json]
        Get-QQDirQuota -Path [Directory Path] [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115009394288-Quotas-in-Qumulo-Core
    #>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
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

		# Directory path -> ID conversion
		if ($id -or $path) {
			if ($path) {
				$htmlPath = ([uri]::EscapeDataString($path))
				# API url definition
				$url = "/v1/files/$htmlPath/info/attributes"

				# API call run
				try {
					$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
					$Id = $($response.id)
				}
				catch {
					$_.Exception.Response
				}
			}

			# API url definition
			$url = "/v1/files/quotas/status/$id"

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
		else {
			return ("Missing parameter!")
		}
	}
	catch {
		$_.Exception.Response
	}
}


function Create-QQDirQuota {
<#
    .SYNOPSIS
        Create a directory quota
    .DESCRIPTION
        Add a directory quota. Quota limit in bytes. 
	.PARAMETER Limit LIMIT
		Base-2 shorthand names are accepted: GB, TB (e.g. 50GB)
	.PARAMETER Id [File ID]
		Directory ID
	.PARAMETER Path [Directory Path]
		Directory path
    .EXAMPLE
        Create-QQDirQuota -Id [File ID] -Limit LIMIT
        Create-QQDirQuota -Path [Directory Path] -Limit LIMIT
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115009394288-Quotas-in-Qumulo-Core
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()] [string]$Limit,
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

		# Directory path -> ID conversion
		if ($id -or $path) {
			if ($path) {
				$htmlPath = ([uri]::EscapeDataString($path))
				# API url definition
				$url = "/v1/files/$htmlPath/info/attributes"

				# API call run
				try {
					$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
					$id = $($response.id)
				}
				catch {
					$_.Exception.Response
				}
			}

			# Human readable capacity definitions -> Byte conversion
			$limit_in_bytes = [int64]($limit)

			# API Request body
			$body = @{
				"id" = $id
				"limit" = [string]$limit_in_bytes
			}

			Write-Debug($body| ConvertTo-Json -Depth 10)

			# API url definition
			$url = "/v1/files/quotas/"

			# API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

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
		else {
			return ("Missing parameter!")
		}
	}
	catch {
		$_.Exception.Response
	}
}

function Update-QQDirQuota {
<#
    .SYNOPSIS
        Update a directory quota
    .DESCRIPTION
        Modify the quota for a given directory.
	.PARAMETER Limit LIMIT
		Base-2 shorthand names are accepted: GB, TB (e.g. 50GB)
	.PARAMETER Id [File ID]
		Directory ID
	.PARAMETER Path [Directory Path]
		Directory path
    .EXAMPLE
        Update-QQDirQuota -Id [File ID] -limit LIMIT
        Update-QQDirQuota -Path [Directory Path] -limit LIMIT
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115009394288-Quotas-in-Qumulo-Core
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()] [string]$Limit,
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

		# Directory path -> ID conversion
		if ($id -or $path) {
			if ($path) {
				$htmlPath = ([uri]::EscapeDataString($path))
				# API url definition		
				$url = "/v1/files/$htmlPath/info/attributes"
				
				# API call run
				try {
					$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
					$id = $($response.id)
				}
				catch {
					$_.Exception.Response
				}
			}

			# Human readable capacity definitions -> Byte conversion 
			$limit_in_bytes = [int64]($limit)

			# API Request body
			$body = @{
				"id" = $id
				"limit" = [string]$limit_in_bytes
			}

			Write-Debug($body| ConvertTo-Json -Depth 10)

			# API url definition
			$url = "/v1/files/quotas/$id"
			
			# API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'PUT' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

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
		else {
			return ("Missing parameter!")
		}
	}
	catch {
		$_.Exception.Response
	}
}

function Delete-QQDirQuota {
<#
    .SYNOPSIS
        Delete a directory quota
    .DESCRIPTION
        Delete the quota for a given directory.
	.PARAMETER Id [File ID]
		Directory ID
	.PARAMETER Path [Directory Path]
		Directory path
    .EXAMPLE
        Delete-QQDirQuota -Id [File ID]
        Delete-QQDirQuota -Path [Directory Path]
    .LINK
		https://care.qumulo.com/hc/en-us/articles/115009394288-Quotas-in-Qumulo-Core
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
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

		# Directory path -> ID conversion
		if ($id -or $path) {
			if ($path) {
				$htmlPath = ([uri]::EscapeDataString($path))
				# API url definition
				$url = "/v1/files/$htmlPath/info/attributes"

				# API call run
				try {
					$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
					$id = $($response.id)
				}
				catch {
					$_.Exception.Response
				}
			}

			# API url definition
			$url = "/v1/files/quotas/$id"
			
			# API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

				if ($Json) {
					return @($response) | ConvertTo-Json -Depth 10
				}
				else {
					return "Directory quota was deleted succesfully."
				}
			}
			catch {
				$_.Exception.Response
			}
		}
		else {
			return ("Missing parameter!")
		}
	}
	catch {
		$_.Exception.Response
	}
}