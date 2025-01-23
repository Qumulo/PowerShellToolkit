<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloTreeDelete.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo directory delete operations
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
function List-QQTreeDeletes {
<#
	.SYNOPSIS
		Tree Delete Job Statuses
	.DESCRIPTION
		Tree Delete Job Statuses
	.EXAMPLE
		List-QQTreeDeletes [-Json]
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
		$url = "/v1/tree-delete/jobs/"

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

function Get-QQTreeDelete {
<#
	.SYNOPSIS
		Status of Directory Tree Deletion
	.DESCRIPTION
		Status of Directory Tree Deletion
	.PARAMETER Id [DIRECTORY_ID]
		Directory id
	.PARAMETER Path [DIRECTORY_PATH]
		Directory path
	.EXAMPLE
		Get-QQTreeDelete -Path [DIRECTORY_PATH] [-Json]
		Get-QQTreeDelete -Id [DIRECTORY_ID] [-Json]
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path
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
		$url = "/v1/tree-delete/jobs/$Id"

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

function Create-QQTreeDelete {
<#
	.SYNOPSIS
		Delete Directory Tree
	.DESCRIPTION
		Delete Directory Tree
	.PARAMETER Id [DIRECTORY_ID]
		Directory id
	.PARAMETER Path [DIRECTORY_PATH]
		Directory path
	.EXAMPLE
		Create-QQTreeDelete -Path [DIRECTORY_PATH] [-Json]
		Create-QQTreeDelete -Id [DIRECTORY_ID] [-Json]
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path
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
		$url = "/v1/tree-delete/jobs/"

		# API request body
		$body = @{ 'id' = $Id }

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
	catch {
		$_.Exception.Response
	}
}

function Cancel-QQTreeDelete {
<#
	.SYNOPSIS
		Cancel a Tree Delete Job
	.DESCRIPTION
		Cancel a Tree Delete Job
	.PARAMETER Id [DIRECTORY_ID]
		Directory id
	.PARAMETER Path [DIRECTORY_PATH]
		Directory path
	.EXAMPLE
		Cancel-QQTreeDelete -Path [DIRECTORY_PATH] [-Json]
		Cancel-QQTreeDelete -Id [DIRECTORY_ID] [-Json]
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path
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
		$url = "/v1/tree-delete/jobs/$Id"

		# API call run	
		try {

			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

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

