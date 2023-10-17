<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloReplication.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo replication configurations and operations
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
function List-QQSourceRelationships {
<#
    .SYNOPSIS
        List existing source replication relationships.
    .DESCRIPTION
        List existing source replication relationships.
    .EXAMPLE
        List-QQSourceRelationships [-Json]
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$json
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
		$url = "/v2/replication/source-relationships/"

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

function List-QQSourceRelationshipStatuses {
<#
    .SYNOPSIS
        List statuses for all existing source replication relationships.
    .DESCRIPTION
        List statuses for all existing source replication relationships.
    .EXAMPLE
        List-QQSourceRelationshipStatuses [-Json]
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$json
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
		$url = "/v2/replication/source-relationships/status/"

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json"

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

function Get-QQSourceRelationship {
<#
    .SYNOPSIS
        Get information about the specified source replication relationship.
    .DESCRIPTION
       Get information about the specified source replication relationship.
	.PARAMETER Id [ID]
		Relationship Id
    .EXAMPLE
        Get-QQSourceRelationship -Id [ID] [-Json]
    #>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$id,
		[Parameter(Mandatory = $False)] [switch]$json
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
		$url = "/v2/replication/source-relationships/$id"

		try {
			# API call run	
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Response	
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

function Get-QQSourceRelationshipStatus {
<#
    .SYNOPSIS
        Get the status of an existing source replication relationship.
    .DESCRIPTION
      Get the status of an existing source replication relationship.
    .PARAMETER Id [ID]
		Relationship Id
	.EXAMPLE
        Get-QQSourceRelationshipStatus -Id [ID] [-Json]
    #>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$id,
		[Parameter(Mandatory = $False)] [switch]$json
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
		$url = "/v2/replication/source-relationships/$id/status"

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

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

function List-QQSourceRelationshipSnapshots {
<#
	.SYNOPSIS
		List All Queued Snapshots for a Source Relationship
	.DESCRIPTION
		List All Queued Snapshots for a Source Relationship
	.PARAMETER Id [ID]
		Relationship Id
	.EXAMPLE
		List-QQSourceRelationshipSnapshots -Id [ID] [-Json]
	#>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$id,
		[Parameter(Mandatory = $False)] [switch]$json
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
		$url = "/v2/replication/source-relationships/$id/queued-snapshots/"

		try {
			# API call run	
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Response	
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

function List-QQTargetRelationshipStatuses {
<#
	.SYNOPSIS
		List statuses for all existing target replication relationships.
	.DESCRIPTION
		List statuses for all existing target replication relationships.
	.EXAMPLE
		List-QQTargetRelationshipStatuses [-Json]
	#>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$json
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
		$url = "/v2/replication/target-relationships/status/"

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json"

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

function Get-QQTargetRelationshipStatus {
<#
	.SYNOPSIS
		Get the status of an existing target replication relationship.
	.DESCRIPTION
		Get the status of an existing target replication relationship.
	.PARAMETER Id [ID]
		Relationship Id
	.EXAMPLE
		Get-QQTargetRelationshipStatus -Id [ID] [-Json]
	#>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$id,
		[Parameter(Mandatory = $False)] [switch]$json
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
		$url = "/v2/replication/target-relationships/$id/status"

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

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

function Create-QQSourceRelationship {
<#
    .SYNOPSIS
        Create a new replication relationship. You need to authorize the relationship on the target cluster after this.
    .DESCRIPTION
        Create a new object replication relationship. You need to authorize the relationship on the target cluster after this.
	.PARAMETER SourceDirectoryId [SOURCE_DIRECTORY_ID] 
		File ID of the source directory
	.PARAMETER SourceDirectoryPath [SOURCE_DIRECTORY_PATH]
		Path to the source directory
    .PARAMETER TargetDirectoryPath [TARGET_DIRECTORY_PATH]
		Path to the target directory       
    .PARAMETER TargetClusterAddress [TARGET_CLUSTER_ADDRESS]
		The target IP address
    .PARAMETER TargetPort [Target_PORT]
		Network port to replicate to on the target (overriding default)
    .PARAMETER EnableReplication [$True|$False]
		Enable replication
    .PARAMETER SetSourceDirectroyReadOnly [$True|$False]
		Set source directory read only
    .PARAMETER MapLocalNFSIds [$True|$False]
		Map local ids to NFS ids
    #>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "SourceDirectoryId")] [string]$SourceDirectoryId,
		[Parameter(Mandatory = $True,ParameterSetName = "SourceDirectoryPath")] [string]$SourceDirectoryPath,
		[Parameter(Mandatory = $True)] [string]$TargetDirectoryPath,
		[Parameter(Mandatory = $True)] [string]$TargetClusterAddress,
		[Parameter(Mandatory = $False)] [string]$TargetPort = "3712",
		[Parameter(Mandatory = $False)] [bool]$EnableReplication = $True,
		[Parameter(Mandatory = $False)] [bool]$SetSourceDirectroyReadOnly = $False,
		[Parameter(Mandatory = $False)] [bool]$MapLocalNFSIds = $True,
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

		# API Request body
		$body = @{
			"source_root_path" = $SourceDirectoryPath
			"target_root_path" = $TargetDirectoryPath
			"target_address" = $TargetClusterAddress
			"target_port" = $TargetPort
			"map_local_ids_to_nfs_ids" = $MapLocalNFSIds
			"replication_enabled" = $EnableReplication
		}

		Write-Debug ($body | ConvertTo-Json -Depth 10)

		# API url definition
		$url = "/v2/replication/source-relationships/"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

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

function Authorize-QQRelationship {
<#
	.SYNOPSIS
		Authorize the specified replication relationship, establishing this cluster as the target of replication.
	.DESCRIPTION
		Authorize the specified replication relationship, establishing this cluster as the target of replication.
	.PARAMETER RelationshipId [RELATIONSHIP_ID] 
		Unique identifier of the target replication relationship
	.PARAMETER AllowNonEmptyDirectory 
		Allow the replication relationship to be authorized on a target directory containing existing data. Existing data in the target
        directory may be deleted or overwritten. If you wish to preserve this data, consider taking a snapshot before authorizing.
	.PARAMETER AllowFSPathCreate
		Set source directory read only
	#>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(

		[Parameter(Mandatory = $True)] [string]$RelationshipID,
		[Parameter(Mandatory = $False)] [bool]$AllowNonEmptyDirectory = $False,
		[Parameter(Mandatory = $False)] [bool]$AllowFSPathCreate = $False,
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
		$url = "/v2/replication/target-relationships/$RelationshipID/"

		if ($AllowNonEmptyDirectory) {
			$url += "authorize?allow-non-empty-directory=true&"
		}
		else {
			$url += "authorize?allow-non-empty-directory=false&"
		}

		if ($AllowFSPathCreate) {
			$url += "allow-fs-path-create=true"
		}
		else {
			$url += "allow-fs-path-create=false"
		}

		Write-Debug ($url | ConvertTo-Json -Depth 10)



		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

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

function Delete-QQSourceRelationship {
<#
	.SYNOPSIS
		Delete the specified source replication relationship.
	.DESCRIPTION
		Delete the specified source replication relationship.
	.PARAMETER RelationshipId [RELATIONSHIP_ID] 
		Unique identifier of the source replication relationship
	.PARAMETER Force
		Do not prompt
	#>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(

		[Parameter(Mandatory = $True)] [string]$RelationshipID,
		[Parameter(Mandatory = $False)] [switch]$Force,
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
		$url = "/v2/replication/source-relationships/$RelationshipID"

		if (-not $Force) {
			$confirmation = Read-Host "Proceed with deletion? (yes/no)"
			if (-not ($confirmation -eq 'yes')) {
				Write-Error "Canceling the source replication delete  request..."; return
			}
		}


		Write-Debug ($url | ConvertTo-Json -Depth 10)



		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

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

function Delete-QQTargetRelationship {
<#
	.SYNOPSIS
		Delete the specified target replication relationship.
	.DESCRIPTION
		Delete the specified target replication relationship.
	.PARAMETER RelationshipId [RELATIONSHIP_ID] 
		Unique identifier of the target replication relationship
	.PARAMETER Force
		Do not prompt
	#>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(

		[Parameter(Mandatory = $True)] [string]$RelationshipID,
		[Parameter(Mandatory = $False)] [switch]$Force,
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
		$url = "/v2/replication/source-relationships/$RelationshipID"

		if (-not $Force) {
			$confirmation = Read-Host "Proceed with deletion? (yes/no)"
			if (-not ($confirmation -eq 'yes')) {
				Write-Error "Canceling the source replication delete  request..."; return
			}
		}


		Write-Debug ($url | ConvertTo-Json -Depth 10)



		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

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

# function Delete-QQObjectRelationship {
# <#
#     .SYNOPSIS
#        Delete the specified object replication relationship, which must not be running a job.
#     .DESCRIPTION
#         Delete the specified object replication relationship, which must not be running a job.
# 	.PARAMETER Id [ID]
# 		Relationship Id
#     .EXAMPLE
#         Delete-QQObjectRelationship -Id [ID]
#     #>

# 	# CmdletBinding parameters
# 	[CmdletBinding()]
# 	param(
# 		[Parameter(Mandatory = $True)] [string]$Id
# 	)
# 	if ($SkipCertificateCheck -eq 'true') {
# 		$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
# 	}

# 	try {
# 		# Existing BearerToken check
# 		if (!$global:Credentials) {
# 			Login-QQCluster
# 		}
# 		else {
# 			if (!$global:Credentials.BearerToken.StartsWith("session-v1")) {
# 				Login-QQCluster
# 			}
# 		}

# 		$bearerToken = $global:Credentials.BearerToken
# 		$clusterName = $global:Credentials.ClusterName
# 		$portNumber = $global:Credentials.PortNumber

# 		$TokenHeader = @{
# 			Authorization = "Bearer $bearerToken"
# 		}

# 		# API url definition
# 		$url = "/v3/replication/object-relationships/$id"

# 		# API call run
# 		try {
# 			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

# 			#  Response
# 			return ("$id was deleted successfully.")
# 		}
# 		catch {
# 			$_.Exception.Response
# 		}
# 	}
# 	catch {
# 		$_.Exception.Response
# 	}
# }

# function Start-QQObjectRelationship {
# <#
#     .SYNOPSIS
#         Start a new replication job for the specified object relationship
#     .DESCRIPTION
#         Start a new replication job for the specified object relationship
# 	.PARAMETER Id [ID]
# 		Relationship Id
#     .EXAMPLE
#         Start-QQObjectRelationship -Id [ID]
#     #>
# 	# CmdletBinding parameters
# 	[CmdletBinding()]
# 	param(
# 		[Parameter(Mandatory = $True)] [string]$Id,
# 		[Parameter(Mandatory = $False)] [switch]$json
# 	)
# 	if ($SkipCertificateCheck -eq 'true') {
# 		$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
# 	}

# 	try {
# 		# Existing BearerToken check
# 		if (!$global:Credentials) {
# 			Login-QQCluster
# 		}
# 		else {
# 			if (!$global:Credentials.BearerToken.StartsWith("session-v1")) {
# 				Login-QQCluster
# 			}
# 		}

# 		$bearerToken = $global:Credentials.BearerToken
# 		$clusterName = $global:Credentials.ClusterName
# 		$portNumber = $global:Credentials.PortNumber

# 		$TokenHeader = @{
# 			Authorization = "Bearer $bearerToken"
# 		}

# 		# API url definition
# 		$url = "/v3/replication/object-relationships/$id/replicate"

# 		# API call run
# 		try {
# 			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

# 			# API url definition
# 			$url = "/v3/replication/object-relationships/$id/status"

# 			# API call run
# 			try {
# 				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

# 				if ($json) {
# 					return @($response) | ConvertTo-Json -Depth 10
# 				}
# 				else {
# 					return $response
# 				}
# 			}
# 			catch {
# 				$_.Exception.Response
# 			}
# 		}
# 		catch {
# 			$_.Exception.Response
# 		}
# 	}
# 	catch {
# 		$_.Exception.Response
# 	}
# }

# function Abort-QQObjectRelationship {
# <#
#     .SYNOPSIS
#         Abort any ongoing replication job for the specified object replication relationship.
#     .DESCRIPTION
#         Abort any ongoing replication job for the specified object replication relationship.
# 	.PARAMETER Id [ID]
# 		Relationship Id
#     .EXAMPLE
#         Abort-QQObjectRelationship -Id [ID]
#     #>
# 	# CmdletBinding parameters
# 	[CmdletBinding()]
# 	param(
# 		[Parameter(Mandatory = $True)] [string]$Id,
# 		[Parameter(Mandatory = $False)] [switch]$json
# 	)
# 	if ($SkipCertificateCheck -eq 'true') {
# 		$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
# 	}

# 	try {
# 		# Existing BearerToken check
# 		if (!$global:Credentials) {
# 			Login-QQCluster
# 		}
# 		else {
# 			if (!$global:Credentials.BearerToken.StartsWith("session-v1")) {
# 				Login-QQCluster
# 			}
# 		}

# 		$bearerToken = $global:Credentials.BearerToken
# 		$clusterName = $global:Credentials.ClusterName
# 		$portNumber = $global:Credentials.PortNumber

# 		$TokenHeader = @{
# 			Authorization = "Bearer $bearerToken"
# 		}

# 		# API url definition
# 		$url = "/v3/replication/object-relationships/$id/abort-replication"

# 		# API call run
# 		try {
# 			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

# 			# API url definition
# 			$url = "/v3/replication/object-relationships/$id/status"

# 			# API call run
# 			try {
# 				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

# 				if ($json) {
# 					return @($response) | ConvertTo-Json -Depth 10
# 				}
# 				else {
# 					return $response
# 				}
# 			}
# 			catch {
# 				$_.Exception.Response
# 			}
# 		}
# 		catch {
# 			$_.Exception.Response
# 		}
# 	}
# 	catch {
# 		$_.Exception.Response
# 	}
# }

