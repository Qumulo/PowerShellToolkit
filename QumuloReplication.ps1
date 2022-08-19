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

# function Create-QQObjectRelationship {
# <#
#     .SYNOPSIS
#         Create a new object replication relationship. Replication will automatically start after the relationship is created.
#     .DESCRIPTION
#         Create a new object replication relationship. Replication will automatically start after the relationship is created.
# 	.PARAMETER LocalDirectoryId [LOCAL_DIRECTORY_ID] 
# 		File ID of the qumulo directory if local_directory_path is not provided
# 	.PARAMETER LocalDirectoryPath [LOCAL_DIRECTORY_PATH]
# 		Path of the qumulo directory if local_directory_id is not provided
#     .PARAMETER Direction [COPY_TO_OBJECT|COPY_FROM_OBJECT]
# 		Whether data is to be copied to, or from, the object store COPY_FROM_OBJECT or COPY_TO_OBJECT
#     .PARAMETER ObjectFolder [OBJECT_FOLDER]
# 		Folder to use in the object store bucket. A slash separator is automatically used to specify a 'folder' in a bucket.
# 	.PARAMETER Bucket [BUCKET]
# 		Bucket in the object store to use for this relationship
#     .PARAMETER Region [REGION]
# 		Region the bucket is located in
#     .PARAMETER AccessKeyId [ACCESS_KEY_ID]
# 		Access key ID to use when communicating with the object store
#     .PARAMETER SecretAccessKey [SECRET_ACCESS_KEY]
# 		Secret access key to use when communicating with the object store
#     .PARAMETER ObjectStoreAddress [OBJECT_STORE_ADDRESS]
# 		S3-compatible server address. For Amazon S3, use s3.<region>.amazonaws.com (e.g., s3.us-west-2.amazonaws.com).         
#     .PARAMETER UsePort [USE_PORT]
# 		HTTPS port to use when communicating with the object store (default: 443)
#     .PARAMETER CACertificate [CA_CERTIFICATE]
# 		Public certificate of the certificate authority to trust for connections to the object store, in PEM format (defaults to built-in trusted public CAs)        
#     .PARAMETER BucketAddressingStyle [BUCKET_STYLE_PATH|BUCKET_STYLE_VIRTUAL_HOSTED]
# 		Addressing style for requests to the bucket. Set to BUCKET_STYLE_PATH for path-style addressing or BUCKET_STYLE_VIRTUAL_HOSTED for virtual hosted-style (the default).
#     #>
# 	# CmdletBinding parameters
# 	[CmdletBinding()]
# 	param(
# 		[Parameter(Mandatory = $True,ParameterSetName = "LocalDirectoryId")] [string]$LocalId,
# 		[Parameter(Mandatory = $True,ParameterSetName = "LocalDirectoryPath")] [string]$LocalPath,
# 		[Parameter(Mandatory = $True)][ValidateSet("Copy_From_Object","Copy_To_Object")][string]$Direction,
# 		[Parameter(Mandatory = $True)] [string]$ObjectFolder,
# 		[Parameter(Mandatory = $True)] [string]$Bucket,
# 		[Parameter(Mandatory = $True)] [string]$Region,
# 		[Parameter(Mandatory = $True)] [string]$AccessKeyId,
# 		[Parameter(Mandatory = $True)] [string]$SecretAccessKey,
# 		[Parameter(Mandatory = $False)] [string]$ObjectStoreAddress,
# 		[Parameter(Mandatory = $False)] [int32]$UsePort=443,
# 		[Parameter(Mandatory = $False)] [string]$CACertificate,
# 		[Parameter(Mandatory = $False)][ValidateSet("Bucket_Style_Path","Bucket_Style_Virtual_Hosted")][string]$BucketAddressingStyle= "BUCKET_STYLE_VIRTUAL_HOSTED",
# 		[Parameter(Mandatory = $False)] [switch]$Json
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

# 		# API Request body

# 		# Local file path -> Local file Id conversion 
# 			if ($localpath) {
# 				$htmlPath = ([uri]::EscapeDataString($localpath))
# 				# API url definition
# 				$url = "/v1/files/$htmlPath/info/attributes"
				
# 				# API call run
# 				try {
# 					$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
# 					$localid = $($response.id)
# 				}
# 				catch {
# 					$_.Exception.Response
# 				}
# 			}

# 			if (!$bucketaddressingstyle) {
# 				$bucketaddressingstyle = "BUCKET_STYLE_VIRTUAL_HOSTED"
# 			}

# 			if (!$useport) {
# 				$useport = 443
# 			}

# 			if (!$objectstoreaddress) {
# 				$objectstoreaddress = "s3.$region.amazonaws.com"
# 			}

# 			$body = @{
# 				"access_key_id" = $AccessKeyId
# 				"secret_access_key" = $SecretAccessKey
# 				"bucket" = $Bucket
# 				"port" = $UsePort
# 				"region" = $Region
# 				"direction" = $Direction.ToUpper()
# 				"local_directory_id" = $LocalId
# 				"object_folder" = $ObjectFolder
# 				"object_store_address" = $ObjectStoreAddress
# 				"bucket_style" = $BucketAddressingStyle
# 			}

# 			if ($CACertificate) {
# 				$body += @{ "ca_certificate" = $CACertificate }
# 			}

# 			Write-Debug($body| ConvertTo-Json -Depth 10)

# 			# API url definition
# 			$url = "/v3/replication/object-relationships/"

# 			# API call run
# 			try {
# 				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

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
# 	}
# 	catch {
# 		$_.Exception.Response
# 	}
# }

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

