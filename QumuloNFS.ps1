<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloSMB.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo SMB configurations and operations
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
function List-QQNFSExports {
	<#
		.SYNOPSIS
			List all NFS exports
		.DESCRIPTION
			List all NFS exports.
		.EXAMPLE
			List-QQNFSExports [-Json]
		.LINK
	
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
	
			Write-Debug ($global:Credentials | ConvertTo-Json -Depth 10)
	
			$TokenHeader = @{
				Authorization = "Bearer $bearerToken"
			}
	
			$url = "/v3/nfs/exports/"
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
	
	function Get-QQNFSExport {
	<#
		.SYNOPSIS
			List a NFS export
		.DESCRIPTION
			Retrieve the specified NFS export. 
		.PARAMETER ExportId [ID]
			A unique identifier of the NFS export (export ID)
		.PARAMETER ExportPath [EXPORT_PATH]
			A unique identifier of the NFS export path
		.EXAMPLE
			Get-QQNFSExport -ExportId [ID] | -ExportPath [EXPORT_PATH] -TenantID [TENANT_ID] [-Json]
		.LINK
	
		#>
		# CmdletBinding parameters.
		[CmdletBinding()]
		param(
			[Parameter(Mandatory = $True,ParameterSetName = "ExportId")] [string]$ExportId,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [string]$ExportPath,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [int16]$TenantID,
			[Parameter(Mandatory = $False)] [switch]$Json
		)
		if ($SkipCertificateCheck -eq 'true') {
			$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
		}
	
		try {
			$foundShare = 0
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
	
			Write-Debug ($global:Credentials | ConvertTo-Json -Depth 10)
	
			$TokenHeader = @{
				Authorization = "Bearer $bearerToken"
			}
	
			$url = "/v3/nfs/exports/"
	
			# API url definition
			if ($ExportId) {
				$url += $ExportId
			}
			elseif ($ExportPath) {
	
				# API call run
				try {
					$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
	
					# Response
					$nfsExports = $response.entries
	
					foreach ($export in $nfsExports) {
						if (($ExportPath -eq $export.export_path) -and ($TenantID -eq $export.tenant_id)) {
							$ExportId = $export.id
							$url += $ExportId
							$foundShare = 1
						}
					}
	
					if ($foundShare -eq 0) {
						Write-Error "No matching export found. Check the export path and tenant id."
						return
					}
				}
				catch {
					$_.Exception.Response
				}
			}
	
			# API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
	
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
	
	function Add-QQNFSExport {
	<#
		.SYNOPSIS
			Add a new NFS export
		.DESCRIPTION 
			Add an NFS export with given options.
		.PARAMETER ExportPath [EXPORT_PATH] 
			The NFS export path
		.PARAMETER FsPath [FS_PATH]
			The filesystem path to NFS export
		.PARAMETER Description [DESCRIPTION]
			Description of this NFS export
		.PARAMETER CreateFSPath [$true|$false]
			Specifies whether the file system path can be created if it does not already exist.
		.PARAMETER ReadOnly [$true|$false]
			Specifies whether the file system path can be created if it does not already exist.
		.PARAMETER TenantID [TENANT_ID]
			ID of the tenant to add the export to
	
		.EXAMPLE
			Add-QQNFSExport -ExportPath EXPORT_PATH -FsPath FS_PATH
				[-Description DESCRIPTION]
				[-CreateFSPath {true,false}]
				[-Readonly {true,false}]
				[-TenantID TENANT_ID]
				[-Json]
			.LINK
	
		#>
		# CmdletBinding parameters.
		[CmdletBinding()]
		param(
			[Parameter(Mandatory = $True)] [string]$ExportPath,
			[Parameter(Mandatory = $True)] [string]$fsPath,
			[Parameter(Mandatory = $False)] [bool]$CreateFSPath = $False,
			[Parameter(Mandatory = $False)] [string]$Description,
			[Parameter(Mandatory = $False)] [bool]$ReadOnly = $False,
			[Parameter(Mandatory = $True)] [int16]$TenantID,
			[Parameter(Mandatory = $False)] [switch]$Json
		)
		if ($SkipCertificateCheck -eq 'true') {
			$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
		}
	
		try {
			$foundShare = 1
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
	
			Write-Debug ($global:Credentials | ConvertTo-Json -Depth 10)
	
			$TokenHeader = @{
				Authorization = "Bearer $bearerToken"
			}
	
			$url = "/v3/nfs/exports/"
	
			# API url definition
			if ($CreateFSPath) {
				$url += "?allow-fs-path-create=true"
			}
			else {
				$url += "?allow-fs-path-create=false"
			}
	
	
	
	
			# API Request body
			$body = @{
				"export_path" = $ExportPath
				"fs_path" = $FsPath
				"description" = $Description
				"tenant_id" = $TenantID
				"restrictions" = @(@{
						"host_restrictions" = @()
						"require_privileged_port" = $false
						"read_only" = $ReadOnly
						"user_mapping" = "NFS_MAP_NONE"
						"map_to_user" = @{
							"id_type" = "LOCAL_USER"
							"id_value" = "0"
						}
	
					})
			}
	
			Write-Debug ($body | ConvertTo-Json -Depth 10)
	
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
	
	function Delete-QQNFSExport {
	<#
		.SYNOPSIS
			Delete a NFS export
		.DESCRIPTION
			Delete an NFS export. Not undoable.
		.PARAMETER ExportId [ID]
			A unique identifier of the SMB share ID
		.PARAMETER ExportPath [ExportPath]
			A unique identifier of the NFS export path
		.EXAMPLE
			Delete-QQNFSExport -Id [ID] | -ExportPath [EXPORT_PATH] -TenantID [TENANT_ID]
		.LINK
	
		#>
		# CmdletBinding parameters.
		[CmdletBinding()]
		param(
			[Parameter(Mandatory = $True,ParameterSetName = "ExportId")] [string]$ExportId,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [string]$ExportPath,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [int16]$TenantID
		)
		if ($SkipCertificateCheck -eq 'true') {
			$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
		}
	
		try {
			$foundShare = 1
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
	
			Write-Debug ($global:Credentials | ConvertTo-Json -Depth 10)
	
			$TokenHeader = @{
				Authorization = "Bearer $bearerToken"
			}
	
			$url = "/v3/nfs/exports/"
			# API url definition
			if ($ExportId) {
				$url += $ExportId
			}
			elseif ($ExportPath) {
	
				# API call run
				try {
					$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
	
					# Response
					$nfsExports = $response.entries
					foreach ($export in $nfsExports) {
						if (($ExportPath -eq $export.export_path) -and ($TenantID -eq $export.tenant_id)) {
							$ExportId = $export.id
							$url += $ExportId
							$foundShare = 1
						}
					}
	
					if ($foundShare -eq 0) {
						Write-Error "No matching export found. Check the export path and tenant id."
						return
					}
				}
				catch {
					$_.Exception.Response
				}
			}
	
			#API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
	
				# Response
				return ("NFS export ($id) was deleted successfully.")
			}
			catch {
				$_.Exception.Response
			}
		}
		catch {
			$_.Exception.Response
		}
	
	
	}
	
	function Modify-QQNFSExport {
	<#
		.SYNOPSIS
			Modify an NFS export
		.DESCRIPTION
			Modify individual attributes of a NFS export.
		.PARAMETER ExportId [EXPORT_ID] 
			The NFS export id
		.PARAMETER ExportPath [EXPORT_PATH] 
			The NFS export path
		.PARAMETER NewExportPath [NEW_EXPORT_PATH] 
			The new NFS export path
		.PARAMETER NewFsPath [NEW_FS_PATH]
			The new filesystem path to NFS export
		.PARAMETER Description [DESCRIPTION]
			Description of this NFS export
		.PARAMETER TenantId [TENANT_ID]
			ID of the tenant the export is in. Only used if using the -ExportPath argument.
		.PARAMETER NewTenantId [TENANT_ID]
			ID of the tenant the export is in. Only used if using the -ExportPath argument.
		.PARAMETER CreateFSPath [$true|$false]
			Specifies whether the file system path can be created if it does not already exist.
		.EXAMPLE
			Modify-QQNFSExport [-Json]
				-ExportPath [EXPORT_PATH] -TenantID [TENANT_ID] | -ExportId [EXPORT_ID] 
				[-Description DESCRIPTION]
				[-CreateFSPath {true,false}]
				[-NewFSPath NEW_FS_PATH]
				[-NewExportPath NEW_EXPORT_PATH]
				[-NewTenantID NewTENANT_ID]
				[-Json]
			.LINK
	
		#>
		# CmdletBinding parameters.
		[CmdletBinding()]
		param(
			[Parameter(Mandatory = $True,ParameterSetName = "ExportId")] [string]$ExportId,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [string]$ExportPath,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [int16]$TenantID,
			[Parameter(Mandatory = $False)] [string]$NewFsPath,
			[Parameter(Mandatory = $False)] [bool]$CreateFSPath = $False,
			[Parameter(Mandatory = $False)] [string]$Description,
			[Parameter(Mandatory = $False)] [string]$NewExportPath,
			[Parameter(Mandatory = $False)] [string]$NewTenantID
		)
		if ($SkipCertificateCheck -eq 'true') {
			$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
		}
	
		try {
			$foundShare = 1
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
	
			Write-Debug ($global:Credentials | ConvertTo-Json -Depth 10)
	
			$TokenHeader = @{
				Authorization = "Bearer $bearerToken"
			}
	
			$url = "/v3/nfs/exports/"
			if ($ExportId) {
				$url += $ExportId
			}
			elseif ($ExportPath) {
	
				# API call run
				try {
					$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
	
					# Response
					$nfsExports = $response.entries
					foreach ($export in $nfsExports) {
						if (($ExportPath -eq $export.export_path) -and ($TenantID -eq $export.tenant_id)) {
							$ExportId = $export.id
							$url += $ExportId
							$foundShare = 1
						}
					}
	
					if ($foundShare -eq 0) {
						Write-Error "No matching export found. Check the export path and tenant id."
						return
					}
				}
				catch {
					$_.Exception.Response
				}
			}
	
			if ($CreateFSPath) {
				$url += "?allow-fs-path-create=true"
			}
			else {
				$url += "?allow-fs-path-create=false"
			}
	
			# API Request body
			$body = @{}
	
	
	
			if ($NewfsPath) {
				$body += @{
					"fs_path" = $NewfsPath
				}
			}
			if ($NewExportPath) {
				$body += @{
					"export_path" = $NewExportPath
				}
			}
			if ($NewTenantID) {
				$body += @{
					"tenant_id" = $NewTenantID
				}
			}
			if ($Description) {
				$body += @{
					"description" = $Description
				}
			}
	
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
	
	function Add-QQNFSExportHostAccess {
	<#
			.SYNOPSIS
				Add an access hosts are granted to an export
			.DESCRIPTION
				Add the access hosts are granted to an export
			.PARAMETER ExportId [EXPORT_ID] 
				The NFS export id
			.PARAMETER ExportPath [EXPORT_PATH] 
				The NFS export path
			.PARAMETER TenantId [TENANT_ID]
				ID of the tenant the export is in. Only used if using the -ExportPath argument.
			.PARAMETER DeleteDefaultHostAccess
				Delete the default host access rule. 
			.PARAMETER HostRestrictions [HOSTS]
				Individual IP addresses, CIDR masks (e.g. 10.1.2.0/24), or ranges (e.g. 10.2.3.23-47, fd00::42:1fff-c000). Export will match all by default.
			.PARAMETER Readonly [$true|$false]
				Export is read-only.
			.PARAMETER RootSquash
				Map access by root to the anonymous user.
			.PARAMETER AllSquash
				Map all access to the anonymous user.
			.PARAMETER AnonLocal
				The name of a local user to squash to.
			.EXAMPLE
				Add-QQNFSExportHostAccess 
					-ExportPath [EXPORT_PATH] -TenantID [TENANT_ID] | -ExportId [EXPORT_ID]
					-HostRestriction [HOSTS]
					-ReadOnly $true
					-RootSquash
					-AllSquash
					-AnonLocal
			.LINK
		
			#>
		# CmdletBinding parameters.
		[CmdletBinding()]
		param(
			[Parameter(Mandatory = $True,ParameterSetName = "ExportId")] [string]$ExportId,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [string]$ExportPath,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [int16]$TenantID,
			[Parameter(Mandatory = $False)] [array]$HostRestrictions,
			[Parameter(Mandatory = $False)] [switch]$DeleteDefaultHostAccess,
			[Parameter(Mandatory = $False)] [switch]$ReadOnly,
			[Parameter(Mandatory = $False)] [switch]$RootSquash,
			[Parameter(Mandatory = $False)] [switch]$AllSquash,
			[Parameter(Mandatory = $False)] [string]$AnonLocal
	
		)
		if ($SkipCertificateCheck -eq 'true') {
			$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
		}
	
		try {
			$foundShare = 1
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
	
			Write-Debug ($global:Credentials | ConvertTo-Json -Depth 10)
	
			$TokenHeader = @{
				Authorization = "Bearer $bearerToken"
			}
	
	
			$url = "/v3/nfs/exports/"
	
	
	
			# API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
	
				$nfsExports = $response.entries
	
	
	
				if ($ExportId) {
					foreach ($export in $nfsExports) {
						if ($ExportId -eq $export.id) {
							$existingRestrictions = $export.restrictions
							$url += $ExportId
							$url += "?allow-fs-path-create=false"
						}
					}
				}
				elseif ($ExportPath) {
					# Response
					$nfsExports = $response.entries
					foreach ($export in $nfsExports) {
						if (($ExportPath -eq $export.export_path) -and ($TenantID -eq $export.tenant_id)) {
							$ExportId = $export.id
							$existingRestrictions = $export.restrictions
							$url += $ExportId
							$url += "?allow-fs-path-create=false"
							$foundShare = 1
						}
					}
	
					if ($foundShare -eq 0) {
						Write-Error "No matching export found. Check the export path and tenant id."
						return
					}
				}
			}
			catch {
				$_.Exception.Response
			}
	
			Write-Debug ($url)
			# API Request body
	
			if ($DeleteDefaultHostAccess) {
				$tempRestrictions = @()
				foreach ($restriction in $existingRestrictions) {
					Write-Host ($restriction.host_restrictions[0])
					if (($restriction.host_restrictions.Count -eq 0) -and ($restriction.user_mapping -eq "NFS_MAP_NONE") -and ($restriction.read_only -eq $false))
					{
						Write-Host ("The default host access rule has been removed...")
					}
					else {
						$tempRestrictions += $restriction
					}
				}
				$existingRestrictions = $tempRestrictions
			}
	
			$newRestriction = @{}
	
			if ($HostRestrictions) {
				$newRestriction += @{
					"host_restrictions" = $HostRestrictions
				}
			}
			if ($RootSquash) {
				$newRestriction += @{
					"user_mapping" = "NFS_MAP_ROOT"
					"map_to_user" = @{
						"id_type" = "LOCAL_USER"
						"id_value" = $AnonLocal
					}
				}
			}
	
			if ($AllSquash) {
				$newRestriction += @{
					"user_mapping" = "NFS_MAP_ALL"
					"map_to_user" = @{
						"id_type" = "LOCAL_USER"
						"id_value" = $AnonLocal
					}
				}
			}
	
			if (-not ($AllSquash -or $RootSquash)) {
				$newRestriction += @{
					"user_mapping" = "NFS_MAP_NONE"
				}
			}
	
			if ($ReadOnly) {
				$newRestriction += @{
					"read_only" = $true
				}
			}
			else {
				$newRestriction += @{
					"read_only" = $false
				}
			}
	
	
			$newRestriction += @{
				"require_privileged_port" = $false
			}
	
			$existingRestrictions += @($newRestriction)
	
			$body = @{
				"restrictions" = $existingRestrictions
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
	
	function List-QQNFSExportHostAccess {
	<#
			.SYNOPSIS
				List the host restrictions of an export
			.DESCRIPTION
				List the host restrictions of an export
			.PARAMETER ExportId [EXPORT_ID] 
				The NFS export id
			.PARAMETER ExportPath [EXPORT_PATH] 
				The NFS export path
			.PARAMETER TenantId [TENANT_ID]
				ID of the tenant the export is in. Only used if using the -ExportPath argument.
			.EXAMPLE
				Add-QQNFSExportHostAccess 
					-ExportPath [EXPORT_PATH] -TenantID [TENANT_ID] | -ExportId [EXPORT_ID]
				.LINK
		
			#>
		# CmdletBinding parameters.
		[CmdletBinding()]
		param(
			[Parameter(Mandatory = $True,ParameterSetName = "ExportId")] [string]$ExportId,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [string]$ExportPath,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [int16]$TenantID
	
		)
		if ($SkipCertificateCheck -eq 'true') {
			$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
		}
	
		try {
			$foundShare = 1
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
	
			Write-Debug ($global:Credentials | ConvertTo-Json -Depth 10)
	
			$TokenHeader = @{
				Authorization = "Bearer $bearerToken"
			}
	
			$url = "/v3/nfs/exports/"
	
	
			# API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
	
				$nfsExports = $response.entries
	
				if ($ExportId) {
					foreach ($export in $nfsExports) {
						if ($ExportId -eq $export.id) {
							$existingRestrictions = $export.restrictions
							Write-Host ($existingRestrictions | ConvertTo-Json -Depth 10)
						}
					}
				}
				elseif ($ExportPath) {
					# Response
					$nfsExports = $response.entries
					foreach ($export in $nfsExports) {
						if (($ExportPath -eq $export.export_path) -and ($TenantID -eq $export.tenant_id)) {
							$existingRestrictions = $export.restrictions
							$i = 1
							$existingRestrictionsWPosition = @()
							foreach ($restriction in $existingRestrictions)
							{
	
								$restriction | Add-Member -MemberType NoteProperty -Name "position" -Value $i.ToString()
	
								$existingRestrictionsWPosition += $restriction
	
								$i = $i + 1
							}
							Write-Host ($existingRestrictionsWPosition | ConvertTo-Json -Depth 10)
							$foundShare = 1
						}
					}
	
					if ($foundShare -eq 0) {
						Write-Error "No matching export found. Check the export path and tenant id."
						return
					}
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
	
	
	function Modify-QQNFSExportHostAccess {
	<#
			.SYNOPSIS
				Modify an access hosts are granted to an export
			.DESCRIPTION
				Modify the access hosts are granted to an export
			.PARAMETER ExportId [EXPORT_ID] 
				The NFS export id
			.PARAMETER ExportPath [EXPORT_PATH] 
				The NFS export path
			.PARAMETER TenantId [TENANT_ID]
				ID of the tenant the export is in. Only used if using the -ExportPath argument.
			.PARAMETER Position [POSITION]
				The position value of the host restriction that you can get List-QQNFSExportHostAccess
			.PARAMETER HostRestrictions [HOSTS]
				Individual IP addresses, CIDR masks (e.g. 10.1.2.0/24), or ranges (e.g. 10.2.3.23-47, fd00::42:1fff-c000). Export will match all by default.
			.PARAMETER Readonly [$true|$false]
				Export is read-only.
			.PARAMETER RootSquash
				Map access by root to the anonymous user.
			.PARAMETER AllSquash
				Map all access to the anonymous user.
			.PARAMETER AnonLocal
				The name of a local user to squash to.
			.EXAMPLE
				Modify-QQNFSExportHostAccess 
					-ExportPath [EXPORT_PATH] -TenantID [TENANT_ID] | -ExportId [EXPORT_ID]
					-Position [POSITION]
					-HostRestriction [HOSTS]
					-ReadOnly $true
					-RootSquash
					-AllSquash
					-AnonLocal
			.LINK
		
			#>
		# CmdletBinding parameters.
		[CmdletBinding()]
		param(
			[Parameter(Mandatory = $True,ParameterSetName = "ExportId")] [string]$ExportId,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [string]$ExportPath,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [int16]$TenantID,
			[Parameter(Mandatory = $True)] [string]$Position,
			[Parameter(Mandatory = $False)] [array]$HostRestrictions,
			[Parameter(Mandatory = $False)] [switch]$ReadOnly,
			[Parameter(Mandatory = $False)] [switch]$RootSquash,
			[Parameter(Mandatory = $False)] [switch]$AllSquash,
			[Parameter(Mandatory = $False)] [string]$AnonLocal
	
		)
		if ($SkipCertificateCheck -eq 'true') {
			$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
		}
	
		try {
			$foundShare = 1
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
	
			Write-Debug ($global:Credentials | ConvertTo-Json -Depth 10)
	
			$TokenHeader = @{
				Authorization = "Bearer $bearerToken"
			}
	
			# Multi-tenancy check
			$tenant_url = "/v1/multitenancy/tenants/"
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$tenant_url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
			$tenants = $response.entries
			Write-Debug ($response | ConvertTo-Json -Depth 10)
	
			# API url definition
			if ($tenants.Count -eq 1) {
				$url = "/v2/nfs/exports/"
			}
			else {
				$url = "/v3/nfs/exports/"
			}
	
	
	
			# API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
	
				$nfsExports = $response.entries
	
				if ($ExportId) {
					foreach ($export in $nfsExports) {
						if ($ExportId -eq $export.id) {
							$ExportId = $export.id
							$existingRestrictions = $export.restrictions
							$url += $ExportId
							$existingRestrictions = $export.restrictions
							$i = 1
							$newRestrictions = @()
							foreach ($restriction in $existingRestrictions)
							{
	
								if ($i -eq $Position) {
									$updatedRestriction = @{}
	
									if ($HostRestrictions) {
										$updatedRestriction += @{
											"host_restrictions" = $HostRestrictions
										}
									}
									if ($RootSquash) {
										$updatedRestriction += @{
											"user_mapping" = "NFS_MAP_ROOT"
											"map_to_user" = @{
												"id_type" = "LOCAL_USER"
												"id_value" = $AnonLocal
											}
										}
									}
	
									if ($AllSquash) {
										$updatedRestriction += @{
											"user_mapping" = "NFS_MAP_ALL"
											"map_to_user" = @{
												"id_type" = "LOCAL_USER"
												"id_value" = $AnonLocal
											}
										}
									}
	
									if (-not ($AllSquash -or $RootSquash)) {
										$updatedRestriction += @{
											"user_mapping" = "NFS_MAP_NONE"
										}
									}
	
									if ($ReadOnly) {
										$updatedRestriction += @{
											"read_only" = $true
										}
									}
									else {
										$updatedRestriction += @{
											"read_only" = $false
										}
									}
	
	
									$updatedRestriction += @{
										"require_privileged_port" = $false
									}
	
									$newRestrictions += $updatedRestriction
								}
								else {
									$newRestrictions += $restriction
								}
								$i = $i + 1
							}
						}
					}
				}
				elseif ($ExportPath) {
					# Response
					$nfsExports = $response.entries
					foreach ($export in $nfsExports) {
						if (($ExportPath -eq $export.export_path) -and ($TenantID -eq $export.tenant_id)) {
							$ExportId = $export.id
							$existingRestrictions = $export.restrictions
							$url += $ExportId
							$i = 1
							$newRestrictions = @()
							foreach ($restriction in $existingRestrictions)
							{
								if ($i -eq $Position) {
									$updatedRestriction = @{}
	
									if ($HostRestrictions) {
										$updatedRestriction += @{
											"host_restrictions" = $HostRestrictions
										}
									}
									if ($RootSquash) {
										$updatedRestriction += @{
											"user_mapping" = "NFS_MAP_ROOT"
											"map_to_user" = @{
												"id_type" = "LOCAL_USER"
												"id_value" = $AnonLocal
											}
										}
									}
	
									if ($AllSquash) {
										$updatedRestriction += @{
											"user_mapping" = "NFS_MAP_ALL"
											"map_to_user" = @{
												"id_type" = "LOCAL_USER"
												"id_value" = $AnonLocal
											}
										}
									}
	
									if (-not ($AllSquash -or $RootSquash)) {
										$updatedRestriction += @{
											"user_mapping" = "NFS_MAP_NONE"
										}
									}
	
									if ($ReadOnly) {
										$updatedRestriction += @{
											"read_only" = $true
										}
									}
									else {
										$updatedRestriction += @{
											"read_only" = $false
										}
									}
	
	
									$updatedRestriction += @{
										"require_privileged_port" = $false
									}
	
									$newRestrictions += $updatedRestriction
								}
								else {
									$newRestrictions += $restriction
								}
								$i = $i + 1
							}
							$foundShare = 1
						}
					}
	
					if ($foundShare -eq 0) {
						Write-Error "No matching export found. Check the export path and tenant id."
						return
					}
				}
			}
			catch {
				$_.Exception.Response
			}
	
	
			# API Request body
	
	
			$body = @{
				"restrictions" = $newRestrictions
			}
	
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
	
	function Remove-QQNFSExportHostAccess {
	<#
			.SYNOPSIS
				Remove an access hosts are granted to an export
			.DESCRIPTION
				Remove the access hosts are granted to an export
			.PARAMETER ExportId [EXPORT_ID] 
				The NFS export id
			.PARAMETER ExportPath [EXPORT_PATH] 
				The NFS export path
			.PARAMETER TenantId [TENANT_ID]
				ID of the tenant the export is in. Only used if using the -ExportPath argument.
			.PARAMETER Position [POSITION]
				The position value of the host restriction that you can get List-QQNFSExportHostAccess
			.EXAMPLE
				Remove-QQNFSExportHostAccess 
					-ExportPath [EXPORT_PATH] -TenantID [TENANT_ID] | -ExportId [EXPORT_ID]
					-Position [POSITION]
				.LINK
		
			#>
		# CmdletBinding parameters.
		[CmdletBinding()]
		param(
			[Parameter(Mandatory = $True,ParameterSetName = "ExportId")] [string]$ExportId,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [string]$ExportPath,
			[Parameter(Mandatory = $True,ParameterSetName = "ExportPath")] [int16]$TenantID,
			[Parameter(Mandatory = $True)] [string]$Position
	
		)
		if ($SkipCertificateCheck -eq 'true') {
			$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
		}
	
		try {
			$foundShare = 1
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
	
			Write-Debug ($global:Credentials | ConvertTo-Json -Depth 10)
	
			$TokenHeader = @{
				Authorization = "Bearer $bearerToken"
			}
	
			$url = "/v3/nfs/exports/"
	
	
			# API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
	
				$nfsExports = $response.entries
	
				if ($ExportId) {
					foreach ($export in $nfsExports) {
						if ($ExportId -eq $export.id) {
							$ExportId = $export.id
							$existingRestrictions = $export.restrictions
							$url += $ExportId
							$existingRestrictions = $export.restrictions
							$i = 1
							$newRestrictions = @()
							foreach ($restriction in $existingRestrictions)
							{
	
								if ($i -ne $Position) {
									$newRestrictions += $restriction
								}
								$i = $i + 1
							}
						}
					}
				}
				elseif ($ExportPath) {
					# Response
					$nfsExports = $response.entries
					foreach ($export in $nfsExports) {
						if (($ExportPath -eq $export.export_path) -and ($TenantID -eq $export.tenant_id)) {
							$ExportId = $export.id
							$existingRestrictions = $export.restrictions
							$url += $ExportId
							$i = 1
							$newRestrictions = @()
							foreach ($restriction in $existingRestrictions)
							{
	
								if ($i -ne $Position) {
									$newRestrictions += $restriction
								}
								$i = $i + 1
							}
							$foundShare = 1
						}
					}
	
					if ($foundShare -eq 0) {
						Write-Error "No matching export found. Check the export path and tenant id."
						return
					}
				}
			}
			catch {
				$_.Exception.Response
			}
	
	
			# API Request body
	
	
			$body = @{
				"restrictions" = $newRestrictions
			}
	
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
	
	function Get-QQNFSSettings {
	<#
		.SYNOPSIS
			Get NFS settings
		.DESCRIPTION
			Get NFS settings
		.EXAMPLE
			Get-QQNFSSettings [-Json]
		.LINK
			https://care.qumulo.com/hc/en-us/articles/360000722428-Create-an-SMB-Share
			https://care.qumulo.com/hc/en-us/articles/115013237727-QQ-CLI-SMB-Shares
			https://care.qumulo.com/hc/en-us/articles/360011328533-SMB-Share-Permissions
			https://care.qumulo.com/hc/en-us/articles/360005375333-Hide-an-SMB-Share
			https://care.qumulo.com/hc/en-us/articles/360041155254-SMB-Host-Restrictions
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
	
			Write-Debug ($global:Credentials | ConvertTo-Json -Depth 10)
	
			$TokenHeader = @{
				Authorization = "Bearer $bearerToken"
			}
	
			# API url definition
			$url = "/v2/nfs/settings"
	
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
	
	
	function Modify-QQNFSSettings {
	<#
		.SYNOPSIS
			Set NFS server settings
		.DESCRIPTION
			Partially set settings for the NFS Server.
		.PARAMETER 	V4Enabled
			Enables mounting with the NFSv4.1 protocol
		.PARAMETER 	V4Disabled
			Disables mounting with the NFSv4.1 protocol
		.PARAMETER Krb5Enabled
			Enables mounting with KRB5 security
		.PARAMETER Krb5Disabled
			Disables mounting with KRB5 security
		.PARAMETER Krb5PEnabled
			Enables mounting with KRB5p security
		.PARAMETER Krb5PEnabled
			Disables mounting with KRB5p security
		.PARAMETER Krb5iEnabled
			Enables mounting with KRB5i security
		.PARAMETER Krb5iEnabled
			Disables mounting with KRB5p security
		.PARAMETER AuthSysEnabled
			Enables mounting with AUTH_SYS security
		.PARAMETER AuthSysEnabled
			Disables mounting with AUTH_SYS security
		.EXAMPLE
			Modify-QQNFSSettings [-Json]
				-V4Enabled
				-V4Disabled
				-Krb5Enabled 
				-Krb5Disabled
				-Krb5pEnabled
				-Krb5pDisabled
				-Krb5iEnabled
				-Krb5iDisabled
				-AuthSysEnabled
				-AuthSysDisabled
			.LINK
	
		#>
		# CmdletBinding parameters.
		[CmdletBinding()]
		param(
			[Parameter(Mandatory = $False)] [switch]$Json,
			[Parameter(Mandatory = $False)] [switch]$V4Enabled,
			[Parameter(Mandatory = $False)] [switch]$Krb5Enabled,
			[Parameter(Mandatory = $False)] [switch]$Krb5pEnabled,
			[Parameter(Mandatory = $False)] [switch]$Krb5iEnabled,
			[Parameter(Mandatory = $False)] [switch]$AuthSysEnabled,
			[Parameter(Mandatory = $False)] [switch]$V4Disabled,
			[Parameter(Mandatory = $False)] [switch]$Krb5Disabled,
			[Parameter(Mandatory = $False)] [switch]$Krb5pDisabled,
			[Parameter(Mandatory = $False)] [switch]$Krb5iDisabled,
			[Parameter(Mandatory = $False)] [switch]$AuthSysDisabled
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
	
			Write-Debug ($global:Credentials | ConvertTo-Json -Depth 10)
	
			$TokenHeader = @{
				Authorization = "Bearer $bearerToken"
			}
	
			# API Request body
			$body = @{}
	
	
	
			if ($V4Enabled) {
				$body += @{
					"v4_enabled" = $true
				}
			}
			elseif ($V4Disabled) {
				$body += @{
					"v4_enabled" = $false
				}
			}
	
			if ($Krb5Enabled) {
				$body += @{
					"krb5_enabled" = $true
				}
			}
			elseif ($Krb5Disabled) {
				$body += @{
					"krb5_enabled" = $false
				}
			}
	
			if ($Krb5pEnabled) {
				$body += @{
					"krb5p_enabled" = $true
				}
			}
			elseif ($Krb5pDisabled) {
				$body += @{
					"krb5p_enabled" = $false
				}
			}
	
			if ($Krb5iEnabled) {
				$body += @{
					"krb5i_enabled" = $true
				}
			}
			elseif ($Krb5iDisabled) {
				$body += @{
					"krb5i_enabled" = $false
				}
			}
	
			if ($AuthSysEnabled) {
				$body += @{
					"auth_sys_enabled" = $true
				}
			}
			elseif ($AuthSysDisabled) {
				$body += @{
					"auth_sys_enabled" = $false
				}
			}
	
	
	
	
			# API url definition
			$url = "/v2/nfs/settings"
	
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