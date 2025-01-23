<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloUpgrades.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo upgrade configurations and operations
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
function Get-QQUpgradeStatus {
<#
    .SYNOPSIS
        Get the status of the upgrade system
    .DESCRIPTION
        Retrieve the current status of the upgrade system.
    .EXAMPLE
        Get-QQUpgradeStatus [-Json]
    .LINK
        
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
		$url = "/v3/upgrade/status"

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


function Verify-QQUpgradeImage {
<#
    .SYNOPSIS
        Verify an image path for upgrade
    .DESCRIPTION
        Verify that the given image can be used to upgrade the cluster and retrieve details about the upgrade that will occur.
    .PARAMETER Path [Image_FS_Path]
        FS path to upgrade image
    .EXAMPLE
        Verify-QQUgradeImage -Path [FS_PATH]
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $True)] [string]$Path
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

		# API body
		$body = @{ 'image_path' = $Path }

		# API url definition
		$url = "/v2/upgrade/verify-image"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
			# Response
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



function Prepare-QQUpgrade {
<#
    .SYNOPSIS
        Prepare for upgrade.
    .DESCRIPTION
        Prepare for upgrade.
    .PARAMETER Path [Image_FS_Path]
        FS path to upgrade image
    .PARAMETER Rolling 
        Prepare for Rolling upgrade
    .PARAMETER AutoCommit
        Trigger commit phase after the prepare has finished
    .EXAMPLE
        Prepare-QQUgrade -Path [FS_PATH]
        Prepare-QQUgrade -Path [FS_PATH] -Rolling
        Prepare-QQUgrade -Path [FS_PATH] -AutoCommit
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $False)] [switch]$Rolling,
		[Parameter(Mandatory = $False)] [switch]$AutoCommit,
		[Parameter(Mandatory = $True)] [string]$Path
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

		# API body
		$body = @{
			'image_path' = $Path
			'auto_commit' = $false
			'do_rolling_reboot' = $false
		}

		if ($Rolling) { $body.do_rolling_reboot = $true }
		if ($AutoCommit) { $body.auto_commit = $true }
		# API url definition
		$url = "/v2/upgrade/prepare"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
			# Response
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

function Commit-QQUpgrade {
<#
    .SYNOPSIS
        Commit a prepared upgrade.
    .DESCRIPTION
        Commit a prepared upgrade.
    .EXAMPLE
        Commit-QQUgrade 
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
		$url = "/v2/upgrade/commit"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
			# Response
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
