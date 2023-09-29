<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloFile.ps1
	Module Name: 	Qumulo 
	Description: 	PowerShell Script (.ps1) for Qumulo file configurations and operations
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
function Get-QQFileAttr {
<#
    .SYNOPSIS
        Retrieve file attributes
    .DESCRIPTION
        Retrieve file attributes
    .PARAMETER Id [Directory or file name]File ID]
        Directory or File ID
    .PARAMETER Path [Directory  or File Path]
        Directory or File path
    .EXAMPLE
        Get-QQFileAttr -Id [Directory or File ID] 
        Get-QQFileAttr -Path [Directory or File Path] 
    #>

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

		if ($path) {
			$htmlPath = ([uri]::EscapeDataString($path))
			# API url definition
			$url = "/v1/files/$htmlPath/info/attributes"
		}
		elseif ($id) {
			$url = "/v1/files/$id/info/attributes"
		}

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

function Get-QQFileAcl {
<#
    .SYNOPSIS
        Get file ACL
    .DESCRIPTION
        Retrieve file ACL
    .PARAMETER Id [Directory or File ID]
        Directory or File ID
    .PARAMETER Path [Directory or FilePath]
        Directory or File path
    .PARAMETER Snapshot [Snapshot ID]
        Snapshot ID to read from
    .EXAMPLE
        Get-QQFileAcl -Id [File ID] 
        Get-QQFileAcl -Path [Directory Path] 
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()] [string]$Snapshot,
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

		if ($path) {
			$htmlPath = ([uri]::EscapeDataString($path))
			# API url definition
			$url = "/v1/files/$htmlPath/info/acl"
		}
		elseif ($id) {
			$url = "/v1/files/$id/info/acl"
		}

		if ($snapshot) {
			$url += "?snapshot=" + $Snapshot
		}

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



function Create-QQNewDir {
<#
        .SYNOPSIS
            Create a new directory 
        .DESCRIPTION
            Create a new directory 
        .PARAMETER Path [Directory Path]
            Directory path
        .PARAMETER Name [New Directory Name]
            Directory name
        .EXAMPLE
            Create-QQNewDir -Path [Directory Path] -Name [Directory Name]
        #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Path,
		[Parameter(Mandatory = $True)] [string]$Name,
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


		$htmlPath = ([uri]::EscapeDataString($path))
		# API url definition
		$url = "/v1/files/$htmlPath/entries/"

		# API Request body
		$body = @{
			"name" = $Name
			"action" = "CREATE_DIRECTORY"
		}


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

function Set-QQFileAttr {
<#
    .SYNOPSIS
        Set file attributes
    .DESCRIPTION
        Set file attributes. Changing owner or mode bits is done POSIX-style; file's ACL is updated to match the requested permissions.
    .PARAMETER Id [Directory or file name]File ID]
        Directory or File ID
    .PARAMETER Path [Directory  or File Path]
        Directory or File path
    .PARAMETER OwnerSID
    Owner SID
    .EXAMPLE
        Set-QQFileAttr -Id [Directory or File ID] 
        Set-QQFileAttr -Path [Directory or File Path] 
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
		[Parameter(Mandatory = $True)] [string]$OwnerSID,
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

		if ($path) {
			$htmlPath = ([uri]::EscapeDataString($path))
			# API url definition
			$url = "/v1/files/$htmlPath/info/attributes"
		}
		elseif ($id) {
			$url = "/v1/files/$id/info/attributes"
		}

		# API body
		$body = @{
			"owner_details" = @{
				"id_type" = "SMB_SID"
				"id_value" = $OwnerSID
			}
		}
		Write-Debug ($body | ConvertTo-Json -Depth 10)

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

function Get-QQFileSamples {
<#
    .SYNOPSIS
        Get a number of sample files from the file system
    .DESCRIPTION
        Get a number of sample files from the file system
    .PARAMETER Id [Directory ID]
        Directory ID
    .PARAMETER Path [Directory Path]
        Directory path
    .PARAMETER Count [COUNT]
        Number of sample
    .PARAMETER SampleBy [capacity,data,file,named_streams]
        Weight the sampling by the value specified: capacity (total bytes used for data and metadata), data (total bytes used for data only), file (file count), named_streams (named stream count)
    .EXAMPLE
        Get-QQFileSamples -Id [File ID] 
        Get-QQFileSamples -Path [Directory Path] 
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
		[Parameter(Mandatory = $True)] [string]$Count,
		[Parameter(Mandatory = $True)] [string]$SampleBy,
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

		if ($path) {
			$htmlPath = ([uri]::EscapeDataString($path))
			# API url definition
			$url = "/v1/files/$htmlPath/sample/?by-value=$SampleBy&limit=$Count"
		}
		elseif ($id) {
			$url = "/v1/files/$id/sample/?by-value=$SampleBy&limit=$Count"
		}

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


function Read-QQDirAggregates {
<#
    .SYNOPSIS
        Read directory aggregation entries
    .DESCRIPTION
        Read directory aggregation entries
    .PARAMETER Id [Directory ID]
        Directory ID
    .PARAMETER Path [Directory Path]
        Directory path
    .PARAMETER Recursive
        Fetch recursive aggregates. Return aggregated data for this directory 
        and its children. It does a breadth-first traversal of directories up 
        to the user-specified limit (see max_entries and max_depth parameters) 
        or system-imposed limit. Directory entries that are smaller than 10% of 
        the directory's total size are omitted.
    .PARAMETER MaxEntries [Count]
        Maximum number of entries to return
    .PARAMETER MaxDepth [Count]
        Maximum depth to recurse when --recursive is set
    .PARAMETER OrderBy [total_blocks,total_datablocks,total_named_stream_datablocks,total_metablocks,total_files,total_directories,total_symlinks,total_other,total_named_streams]
        Specify field used for top N selection and sorting
    .PARAMETER Snapshot [Snapshot ID]
        Snapshot ID to read from
    .EXAMPLE
        Read-QQDirAggregates -Id [File ID] 
        Read-QQDirAggregates -Path [Directory Path] 
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
		[Parameter(Mandatory = $False)] [switch]$Recursive,
		[Parameter(Mandatory = $False)] [string]$MaxEntries,
		[Parameter(Mandatory = $False)] [string]$MaxDepth,
		[Parameter(Mandatory = $False)] [string]$Snapshot,
		[Parameter(Mandatory = $False)][ValidateSet("total_blocks","total_datablocks","total_named_stream_datablocks","total_metablocks","total_files","total_directories","total_symlinks","total_other","total_named_streams")] [string]$OrderBy,
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

		# /v1/files/%2F/aggregates/
		# /v1/files/%2F/recursive-aggregates/
		# /v1/files/%2F/aggregates/?max-entries=1
		# /v1/files/%2F/aggregates/?max-depth=1
		# /v1/files/%2F/aggregates/?max-entries=1&max-depth=1
		# /v1/files/%2F/aggregates/?order-by=total_directories
		# /v1/files/%2F/aggregates/?max-entries=1&max-depth=1&order-by=total_directories
		# /v1/files/%2F/aggregates/?max-entries=1&max-depth=1&order-by=total_directories&snapshot=18107

		if ($path) {
			$htmlPath = ([uri]::EscapeDataString($path))
			# API url definition
			$url = "/v1/files/$htmlPath/"
		}
		elseif ($id) {
			$url = "/v1/files/$id/"
		}

		if ($Recursive) {
			$url += "recursive-aggregates/"
		}
		else {
			$url += "aggregates/"
		}
		if ($PSBoundParameters.Count -eq 2) {
			if ($maxEntries) {
				$url += "?max-entries=$maxEntries"
			}
			elseif ($maxDepth) {
				$url += "?max-depth=$maxDepth"
			}
			elseif ($OrderBy) {
				$url += "?order-by=$orderBy"
			}
			elseif ($snapshot) {
				$url += "?snapshot=$snapShot"
			}
		}
		elseif ($PSBoundParameters.Count -gt 2) {
			if ($maxEntries) {
				$url += "?max-entries=$maxEntries&"
			}
			if ($MaxDepth) {
				$url += "?max-entries=$maxDepth&"
			}
			if ($OrderBy) {
				$url += "?order-by=$orderBy&"
			}
			if ($snapshot) {
				$url += "?snapshot=$snapShot"
			}
		}
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

function Read-QQDir {
<#
    .SYNOPSIS
        Read directory 
    .DESCRIPTION
        Read directory 
    .PARAMETER Id [Directory ID]
        Directory ID
    .PARAMETER Path [Directory Path]
        Directory path
    .PARAMETER PageSize [Count]
        Max directory entries to return per request
    .PARAMETER Snapshot [Snapshot ID]
        Snapshot ID to read from
    .EXAMPLE
        Read-QQDir -Id [File ID] 
        Read-QQDir -Path [Directory Path] 
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
		[Parameter(Mandatory = $False)] [string]$PageSize,
		[Parameter(Mandatory = $False)] [string]$Snapshot,
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

		if ($path) {
			$htmlPath = ([uri]::EscapeDataString($path))
			# API url definition
			$url = "/v1/files/$htmlPath/entries/"

		}
		elseif ($id) {
			$url = "/v1/files/$id/entries/"
		}

		if ($pageSize -and $snapShot) {
			$url += "?limit=$pageSize&?snapshot=$snapShot"
		}
		else {
			if ($pageSize) {
				$url += "?limit=$pageSize"
			}
			elseif ($snapshot) {
				$url += "?snapshot=$snapShot"
			}
		}

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

function Resolve-QQFilePath {
<#
    .SYNOPSIS
        Resolve file IDs to paths
    .DESCRIPTION
        Return the full paths for each specified file ID. If a file has more than one path (due to hard links) a canonical path is chosen.
    .PARAMETER Ids [File IDS]
        File IDs to resolve. The IDs should be in brackets (example '1202000003').
    .PARAMETER Snapshot [Snapshot ID]
        Snapshot ID to read from
    .EXAMPLE
        Resolve-QQFilePath -Ids '1202000003','1207030003' [-Json]
    #>

	[CmdletBinding(DefaultParameterSetName = 'None')]
	param(
		[Parameter(Mandatory = $True)] [string]$Ids,
		[Parameter(Mandatory = $False)] [string]$Snapshot,
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
		if ($Snapshot) {
			$url = "/v1/files/resolve?snapshot=$Snapshot"
		}
		else {
			$url = "/v1/files/resolve"
		}


		# API body definition
		$body = $Ids.Split(",")
		Write-Debug ($body | ConvertTo-Json -Depth 10)

		# API call ru
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body (@($body) | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

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


function List-QQNamedStreams {
<#
    .SYNOPSIS
        List all named streams on file or directory
    .DESCRIPTION
        List all named streams on provided object
    .PARAMETER Id [Directory ID]
        Directory ID
    .PARAMETER Path [Directory Path]
        Directory path
    .PARAMETER Snapshot [Snapshot ID]
        Snapshot ID to read from
    .EXAMPLE
        List-QQNamedStreams -Id [File ID] 
        List-QQNamedStreams -Path [Directory Path] 
        List-QQNamedStreams -Path [Directory Path] -Snapshot [ID]
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
		[Parameter(Mandatory = $False)] [string]$Snapshot,
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

		if ($path) {
			$htmlPath = ([uri]::EscapeDataString($path))
			# API url definition
			$url = "/v1/files/$htmlPath/streams/"

		}
		elseif ($id) {
			$url = "/v1/files/$id/streams/"
		}

		if ($snapshot) {
			$url += "?snapshot=$snapShot"
		}

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
