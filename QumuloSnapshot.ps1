<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloSnapshot.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo snapshots configurations and operations
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
function List-QQSnapshots {
<#
    .SYNOPSIS
        List all snapshots
    .DESCRIPTION
        List all snapshots
	.PARAMETER All
		List all snapshots
	.PARAMETER ExcludeInDelete
		Exclude all snapshots in process of being deleted.
	.PARAMETER OnlyInDelete
		Display only snapshots in process of being deleted.
    .EXAMPLE
        List-QQSnapshots [-All|-ExcludeInDelete|-OnlyInDelete] [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115010238208-Snapshots-Deep-Dive
		https://care.qumulo.com/hc/en-us/articles/115012699607-Snapshots-Per-Directory-Snapshots
    #>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False,ParameterSetName = "All")] [switch]$All,
		[Parameter(Mandatory = $True,ParameterSetName = "ExcludeInDelete")] [switch]$ExcludeInDelete,
		[Parameter(Mandatory = $True,ParameterSetName = "OnlyInDelete")] [switch]$OnlyInDelete,
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
		if ($ExcludeInDelete) {
			$url = "/v3/snapshots/?filter=exclude_in_delete"
		}
		elseif ($OnlyInDelete) {
			$url = "/v3/snapshots/?filter=only_in_delete"
		}
		else {
			$url = "/v3/snapshots/?filter=all"
		}

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Response
			if ($Json) {
				return @($response.entries) | ConvertTo-Json -Depth 10
			}
			else {
				return $response.entries
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

function List-QQSnapshotStatuses {
<#
    .SYNOPSIS
        List all snapshot statuses
    .DESCRIPTION
        List all snapshot statuses
	.PARAMETER All
		List all snapshots
	.PARAMETER ExcludeInDelete
		Exclude all snapshots in process of being deleted.
	.PARAMETER OnlyInDelete
		Display only snapshots in process of being deleted.
    .EXAMPLE
        List-QQSnapshotStatuses [-All|-ExcludeInDelete|-OnlyInDelete] [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115010238208-Snapshots-Deep-Dive
		https://care.qumulo.com/hc/en-us/articles/115012699607-Snapshots-Per-Directory-Snapshots
    #>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False,ParameterSetName = "All")] [switch]$All,
		[Parameter(Mandatory = $True,ParameterSetName = "ExcludeInDelete")] [switch]$ExcludeInDelete,
		[Parameter(Mandatory = $True,ParameterSetName = "OnlyInDelete")] [switch]$OnlyInDelete,
		[Parameter(Mandatory = $False)] [switch]$Json
	)
	if ($SkipCertificateCheck -eq 'true') {
		$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
	}

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
		if ($ExcludeInDelete) {
			$url = "/v3/snapshots/status/?filter=exclude_in_delete"
		}
		elseif ($OnlyInDelete) {
			$url = "/v3/snapshots/status/?filter=only_in_delete"
		}
		else {
			$url = "/v3/snapshots/status/?filter=all"
		}

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Response
			if ($Json) {
				return @($response.entries) | ConvertTo-Json -Depth 10
			}
			else {
				return $response.entries
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

function Get-QQSnapshot {
<#
	.SYNOPSIS
		Get a single snapshot.
	.DESCRIPTION
		Get a single snapshot.
	.PARAMETER Id [ID]
		Identifier of the snapshot to list.
	.EXAMPLE
		Get-QQSnapshot -id [ID] [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115010238208-Snapshots-Deep-Dive
		https://care.qumulo.com/hc/en-us/articles/115012699607-Snapshots-Per-Directory-Snapshots
	#>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$id,
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

		# API url definition
		$url = "/v2/snapshots/$id"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			#  Response
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
function Get-QQSnapshotStatus {
<#
		.SYNOPSIS
			Get a snaphot status
		.DESCRIPTION
			Get a snapshot status
		.PARAMETER Id [ID]
			Identifier of the snapshot to list.
		.EXAMPLE
			Get-QQSnapshotStatus -Id [ID] [-Json]
		.LINK
			https://care.qumulo.com/hc/en-us/articles/115010238208-Snapshots-Deep-Dive
			https://care.qumulo.com/hc/en-us/articles/115012699607-Snapshots-Per-Directory-Snapshots
		#>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Id,
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
		$url = "/v3/snapshots/status/$id"

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			#  Response
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

function Delete-QQSnapshot {
<#
	.SYNOPSIS
		Delete a single snapshot.
	.DESCRIPTION
		Deletes a single snapshot.
	.PARAMETER Id [ID]
		Identifier of the snapshot to list.
	.EXAMPLE
		Delete-QQSnapshot -id [ID] [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115010238208-Snapshots-Deep-Dive
		https://care.qumulo.com/hc/en-us/articles/115012699607-Snapshots-Per-Directory-Snapshots
	#>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Id,
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
		$url = "/v3/snapshots/$id"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			#  Response
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


function Create-QQSnapshot {
<#
    .SYNOPSIS
        Create a directory snapshot
    .DESCRIPTION
        Create a new snapshot and return snapshot information.
	.PARAMETER SourceFileID [ID]
		ID of directory to snapshot
	.PARAMETER Path [PATH]
		Path of directory to snapshot
	.PARAMETER Expiration [EXPIRATION]
		Time of snapshot expiration. An empty string indicates that the snapshot never expires. The time format follows RFC 3339, a normalized subset of ISO 8601.
	.PARAMETER Name [NAME]
		Snapshot name
    .EXAMPLE
		Create-QQSnapshot  -SourceFileId [SOURCE_FILE_ID]|-Path [PATH] -Expiration [EXPIRATION] -Name [NAME]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115010238208-Snapshots-Deep-Dive
		https://care.qumulo.com/hc/en-us/articles/115012699607-Snapshots-Per-Directory-Snapshots
    #>

	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$SourceFileId,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
		[Parameter(Mandatory = $False)] [string]$Name,
		[Parameter(Mandatory = $False)] [string]$Expiration,
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

		# Directory Path -> SourceFileID conversion
		if ($Path) {
			$htmlPath = ([uri]::EscapeDataString($path))

			# API url definition
			$url = "/v1/files/$htmlPath/info/attributes"
			# API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
				$SourceFileId = $($response.id)
			}
			catch {
				$_.Exception.Response
			}
		}

		# API Request body
		$body = @{
			"name_suffix" = $Name
			"expiration" = $Expiration
			"source_file_id" = $SourceFileId
		}

		# API url definition
		$url = "/v3/snapshots/"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

			#  Response
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

function Modify-QQSnapshot {
<#
	.SYNOPSIS
        Modifies a snapshot.
    .DESCRIPTION
        Modifies a snapshot.
	.PARAMETER Id [ID]
		The unique snapshot identifier.
	.PARAMETER Expiration [EXPIRATION]
		Time of snapshot expiration. An empty string indicates that the snapshot never expires. The time format follows RFC 3339, a normalized subset of ISO 8601.
    .EXAMPLE
		Modify-QQSnapshot  -Id [ID] -Expiration [EXPIRATION]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115010238208-Snapshots-Deep-Dive
		https://care.qumulo.com/hc/en-us/articles/115012699607-Snapshots-Per-Directory-Snapshots
    #>

	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Id,
		[Parameter(Mandatory = $False)] [string]$Expiration,
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

		# API Request body
		$body = @{}

		# API url definition
		$url = "/v3/snapshots/$id"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

			#  Response
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

function Get-QQSnapshotsCapacityUsage {
<#
	.SYNOPSIS
		Get the total space consumed by all snapshots.
	.DESCRIPTION
		Returns the approximate amount of space for each snapshot that would be reclaimed if that snapshot were deleted.
	.EXAMPLE
		Get-QQSnapshotsCapacityUsage [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115010238208-Snapshots-Deep-Dive
		https://care.qumulo.com/hc/en-us/articles/115012699607-Snapshots-Per-Directory-Snapshots
    #>

	# CmdletBinding parameters.
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
		$url = "/v1/snapshots/capacity-used-per-snapshot/"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			#  Response
			if ($Json) {
				return @($response.entries) | ConvertTo-Json -Depth 10
			}
			else {
				return $response.entries
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

function Get-QQSnapshotCapacityUsage {
<#
	.SYNOPSIS
		Get the approximate amount of space for each snapshot that would be reclaimed if that snapshot were deleted.
	.DESCRIPTION
		Returns the approximate amount of space that would be reclaimed if the given snapshot were deleted.
	.PARAMETER Id [ID]
		Snapshot ID
	.EXAMPLE
		Get-QQSnapshotsCapacityUsage -Id [ID] [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115010238208-Snapshots-Deep-Dive
		https://care.qumulo.com/hc/en-us/articles/115012699607-Snapshots-Per-Directory-Snapshots
    #>

	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Id,
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
		$url = "/v1/snapshots/capacity-used-per-snapshot/$id"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			#  Response
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

function Get-QQSnapshotsAllCapacityUsage {
<#
	.SYNOPSIS
		Returns approximate amount of space that would be reclaimed if all snapshots were deleted.
	.DESCRIPTION
		Returns approximate amount of space that would be reclaimed if all snapshots were deleted.
	.EXAMPLE
		Get-QQSnapshotsAllCapacityUsage [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115010238208-Snapshots-Deep-Dive
		https://care.qumulo.com/hc/en-us/articles/115012699607-Snapshots-Per-Directory-Snapshots
	#>

	# CmdletBinding parameters.
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
		$url = "/v1/snapshots/total-used-capacity"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			#  Response
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

