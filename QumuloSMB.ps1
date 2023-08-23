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
function List-QQSMBShares {
<#
    .SYNOPSIS
        List all SMB shares
    .DESCRIPTION
        List all SMB shares.
    .EXAMPLE
        List-QQSMBShares [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/360000722428-Create-an-SMB-Share
		https://care.qumulo.com/hc/en-us/articles/115013237727-QQ-CLI-SMB-Shares
		https://care.qumulo.com/hc/en-us/articles/360011328533-SMB-Share-Permissions
		https://care.qumulo.com/hc/en-us/articles/360005375333-Hide-an-SMB-Share
		https://care.qumulo.com/hc/en-us/articles/360041155254-SMB-Host-Restrictions
    #>

	# CmdletBinding parameters.
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

		Write-Debug ($global:Credentials|ConvertTo-Json -Depth 10)

		$TokenHeader = @{
			Authorization = "Bearer $bearerToken"
		}

		# API url definition
		$url = "/v2/smb/shares/"

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

function List-QQSMBShare {
<#
    .SYNOPSIS
        List a SMB share
    .DESCRIPTION
        Retrieve the specified SMB share. 
	.PARAMETER Id [ID]
		A unique identifier of the SMB share (share ID)
	.PARAMETER Name [Name]
		A unique identifier of the SMB share name
    .EXAMPLE
        List-QQSMBShares -Id [ID] | -Name [NAME] [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/360000722428-Create-an-SMB-Share
		https://care.qumulo.com/hc/en-us/articles/115013237727-QQ-CLI-SMB-Shares
		https://care.qumulo.com/hc/en-us/articles/360011328533-SMB-Share-Permissions
		https://care.qumulo.com/hc/en-us/articles/360005375333-Hide-an-SMB-Share
		https://care.qumulo.com/hc/en-us/articles/360041155254-SMB-Host-Restrictions
    #>
	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Name")][string]$Name,
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

		Write-Debug ($global:Credentials|ConvertTo-Json -Depth 10)

		$TokenHeader = @{
			Authorization = "Bearer $bearerToken"
		}

		# API url definition
		if ($Id) {
			$url = "/v2/smb/shares/$Id"
		}
		elseif ($Name) {
			$url = "/v2/smb/shares/$Name"
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

function Add-QQSMBShare{
<#
    .SYNOPSIS
        Add a new SMB share
    .DESCRIPTION 
		Add an SMB share with given options.
	.PARAMETER Name [NAME] 
		The SMB share name
	.PARAMETER FsPath [FS_PATH]
		The filesystem path to SMB share
    .PARAMETER Description [DESCRIPTION]
		Description of this SMB share
    .PARAMETER AccessBasedEnumerationEnabled [$true|$false]
		Enable Access-based Enumeration on this SMB share
    .PARAMETER CreateFSPath [$true|$false]
		Specifies whether the file system path can be created if it does not already exist.
    .PARAMETER DefaultFileCreateMode DEFAULT_FILE_CREATE_MODE]
		Default POSIX file create mode bits on this SMB share (octal, default 0644 if this field is empty)
    .PARAMETER DefaultDirectoryCreateMode DEFAULT_DIRECTORY_CREATE_MODE]
		Default POSIX directory create mode bits on this SMB share (octal, default 0755 if this field is empty)
    .PARAMETER RequireEncryption {true,false}] [--json]
		Require all traffic to this share to be encrypted. Clients without encryption capabilities will not be able to connect. Default is false if this field is empty.
    .PARAMETER NoAccess
		Grant no access.
	.PARAMETER ReadOnly
		Grant everyone except guest read-only access.
	.PARAMETER AllAccess
		Grant everyone except guest full access.
    .PARAMETER GrantReadAccess [TRUSTEE]
		Grant read access to these trustees. e.g. Everyone, uid:1000, gid:1001, sid:S-1-5-2-3-4, or auth_id:500
    .PARAMETER GrantReadWriteAccess [TRUSTEE ...]
		Grant read-write access to these trustees.
    .PARAMETER GrantAllAccess [TRUSTEE ...]
		Grant all access to these trustees.
    .PARAMETER DenyAccess [TRUSTEE ...]
		Deny all access to these trustees.
    .PARAMETER FullControlHosts [RANGE ...]
		Address ranges which should be permitted all access that is also granted by share permissions and file permissions. May be individual IP addresses, CIDR masks (e.g. 10.1.2.0/24), or ranges (e.g. 10.2.3.23-47, fd00::42:1fff-c000).
    .PARAMETER ReadOnlyHosts [RANGE ...]
		Address ranges which should be permitted read-only access at most.
    .PARAMETER DenyHosts [RANGE ...] 
		Address ranges which should be denied access to this share, regardless of other permissions.
	.PARAMETER DenyAllHosts
		Deny all access to this share.
    .EXAMPLE
        Add-QQSMBShares -Name NAME -FsPath FS_PATH
			[-Description DESCRIPTION]
			[-AccessBasedEnumerationEnabled {true,false}]
			[-CreateFSPath {true,false}]
			[-DefaultFileCreateMode DEFAULT_FILE_CREATE_MODE]
			[-DefaultDirectoryCreateMode DEFAULT_DIRECTORY_CREATE_MODE]
			[-RequireEncryption {true,false}]
			[-NoAccess | ReadOnly | AllAccess]
			[-GrantReadAccess TRUSTEE [TRUSTEE ...]
			[-GrantReadWriteAccess TRUSTEE [TRUSTEE ...]
			[-GrantAllAccess TRUSTEE [TRUSTEE ...]
			[-DenyAccess TRUSTEE [TRUSTEE ...]
			[-FullControlHosts RANGE [RANGE ...]
			[-ReadOnlyHosts RANGE [RANGE ...]
			[-DenyHosts RANGE [RANGE ...]
			[-DenyAllHosts]
			[-Json]
		.LINK
			https://care.qumulo.com/hc/en-us/articles/360000722428-Create-an-SMB-Share
			https://care.qumulo.com/hc/en-us/articles/115013237727-QQ-CLI-SMB-Shares
			https://care.qumulo.com/hc/en-us/articles/360011328533-SMB-Share-Permissions
			https://care.qumulo.com/hc/en-us/articles/360005375333-Hide-an-SMB-Share
			https://care.qumulo.com/hc/en-us/articles/360041155254-SMB-Host-Restrictions
    #>
	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)][string]$Name,
		[Parameter(Mandatory = $True)][string]$fsPath,
		[Parameter(Mandatory = $False)] [bool]$CreateFSPath=$False,
		[Parameter(Mandatory = $False)] [string]$Description,
		[Parameter(Mandatory = $False)] [string]$DefaultFileCreateMode="0644",
		[Parameter(Mandatory = $False)] [string]$DefaultDirCreateMode="0755",
		[Parameter(Mandatory = $False)] [bool]$AccessBasedEnumaration = $False,
		[Parameter(Mandatory = $False)] [bool]$Encryption = $False,
		[Parameter(Mandatory = $False)] [switch]$NoAccess,
		[Parameter(Mandatory = $False)] [switch]$DenyAllHosts,
		[Parameter(Mandatory = $False)] [array]$ReadOnly,
		[Parameter(Mandatory = $False)] [array]$AllAccess,
		[Parameter(Mandatory = $False)] [array]$GrantReadAccess,
		[Parameter(Mandatory = $False)] [array]$GrantReadWriteAccess,
		[Parameter(Mandatory = $False)] [array]$GrantAllAccess,
		[Parameter(Mandatory = $False)] [array]$DenyAccess,
		[Parameter(Mandatory = $False)] [array]$ReadOnlyHosts,
		[Parameter(Mandatory = $False)] [array]$DenyHosts,
		[Parameter(Mandatory = $False)] [array]$FullControlHosts,
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

		Write-Debug ($global:Credentials|ConvertTo-Json -Depth 10)

		$TokenHeader = @{
			Authorization = "Bearer $bearerToken"
		}

		# API url definition
		if ($CreateFSPath) {
			$url = "/v2/smb/shares/?allow-fs-path-create=true"
		}
		else {
			$url = "/v2/smb/shares/?allow-fs-path-create=false"
		}

		# Trustee (User & Group) Share Permissions
		if ($noAccess) {
			$permissions = @()
		}
		else {
			$permissions = @()
			if ($readOnly) {
				foreach ($trustee in $ReadOnly) {
					if ($trustee.Contains(':'))
					{
						$trusteeArray = $trustee.Split(":")
						$trusteeHash = @{ $trusteeArray[0] = $trusteeArray[1] }
					}
					else {
						$trusteeHash = @{ Name = $trustee }
					}
					$permissions += (
						@{
							type = "ALLOWED"
							trustee = $trusteeHash
							rights = @(
								"READ"
							)
						}
					)
				}
			}
			if ($allAccess) {
				foreach ($trustee in $allAccess) {
					if ($trustee.Contains(':'))
					{
						$trusteeArray = $trustee.Split(":")
						$trusteeHash = @{ $trusteeArray[0] = $trusteeArray[1] }
					}
					else {
						$trusteeHash = @{ Name = $trustee }
					}
					$permissions += (
						@{
							type = "ALLOWED"
							trustee = $trusteeHash
							rights = @(
								"ALL"
							)
						}
					)
				}
			}
			if ($GrantReadAccess) {
				foreach ($trustee in $GrantReadAccess) {
					if ($trustee.Contains(':'))
					{
						$trusteeArray = $trustee.Split(":")
						$trusteeHash = @{ $trusteeArray[0] = $trusteeArray[1] }
					}
					else {
						$trusteeHash = @{ Name = $trustee }
					}
					$permissions += (
						@{
							type = "ALLOWED"
							trustee = $trusteeHash
							rights = @(
								"READ"
							)
						}
					)
				}
			}
			if ($GrantReadWriteAccess) {
				foreach ($trustee in $GrantReadWriteAccess) {
					if ($trustee.Contains(':'))
					{
						$trusteeArray = $trustee.Split(":")
						$trusteeHash = @{ $trusteeArray[0] = $trusteeArray[1] }
					}
					else {
						$trusteeHash = @{ Name = $trustee }
					}
					$permissions += (
						@{
							type = "ALLOWED"
							trustee = $trusteeHash
							rights = @(
								"READ",
								"WRITE"
							)
						}
					)
				}
			}
			if ($grantAllAccess) {
				foreach ($trustee in $grantAllAccess) {
					if ($trustee.Contains(':'))
					{
						$trusteeArray = $trustee.Split(":")
						$trusteeHash = @{ $trusteeArray[0] = $trusteeArray[1] }
					}
					else {
						$trusteeHash = @{ Name = $trustee }
					}
					$permissions += (
						@{
							type = "ALLOWED"
							trustee = $trusteeHash
							rights = @(
								"ALL"
							)
						}
					)
				}
			}
			if ($DenyAccess) {
				foreach ($trustee in $DenyAccess) {
					if ($trustee.Contains(':'))
					{
						$trusteeArray = $trustee.Split(":")
						$trusteeHash = @{ $trusteeArray[0] = $trusteeArray[1] }
					}
					else {
						$trusteeHash = @{ name = $trustee }
					}
					$permissions += (
						@{
							type = "DENIED"
							trustee = $trusteeHash
							rights = @(
								"ALL"
							)
						}
					)
				}
			}
		}

		# Host Restriction Permissions
		if (!$ReadOnlyHosts -or !$DenyHosts -or !$FullControlHosts -or !$DenyAllHosts)
		{
			$networkPermissions = @(
				@{
					type = "ALLOWED"
					address_ranges = @()
					rights = @(
						"READ",
						"WRITE",
						"CHANGE_PERMISSIONS"
					)
				}
			)
		}
		else {
			$networkPermissions = @()
			if ($ReadOnlyHosts) {
				$networkPermissions += (
					@{
						type = "DENIED"
						address_ranges = $ReadOnlyHosts
						rights = @(
							"WRITE",
							"CHANGE_PERMISSIONS"
						)
					},
					@{
						type = "ALLOWED"
						address_ranges = $ReadOnlyHosts
						rights = @(
							"READ"
						)
					}
				)
			}
			if ($DenyHosts) {
				$networkPermissions += (
					@{
						type = "DENIED"
						address_ranges = $DenyHosts
						rights = @(
							"ALL"
						)
					}
				)
			}
			if ($FullControlHosts) {
				$networkPermissions += (
					@{
						type = "ALLOWED"
						address_ranges = $FullControlHosts
						rights = @(
							"ALL"
						)
					}
				)
			}
			if ($DenyAllHosts) {
				$networkPermissions += (
					@{
						type = "DENIED"
						address_ranges = $DenyAllHosts
						rights = @(
							"ALL"
						)
					}
				)
			}

		}

		# API Request body
		$body = @{
			"share_name" = $Name
			"fs_path" = $FsPath
			"description" = $Description
			"permissions" = $Permissions
			"network_permissions" = $networkPermissions
			"access_based_enumeration_enabled" = $AccessBasedEnumaration
			"default_file_create_mode" = $DefaultFileCreateMode
			"default_directory_create_mode" = $DefaultDirCreateMode
			"require_encryption" = $Encryption
		}

		Write-Debug($body| ConvertTo-Json -Depth 10)
		
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

function Delete-QQSMBShare {
<#
    .SYNOPSIS
        Delete a SMB share
    .DESCRIPTION
        Delete an SMB share. Not undoable.
	.PARAMETER Id [ID]
		A unique identifier of the SMB share ID
	.PARAMETER Name [NAME]
		A unique identifier of the SMB share name
    .EXAMPLE
        Delete-QQSMBShares -Id [ID] | -Name [NAME] 
	.LINK
		https://care.qumulo.com/hc/en-us/articles/360000722428-Create-an-SMB-Share
		https://care.qumulo.com/hc/en-us/articles/115013237727-QQ-CLI-SMB-Shares
		https://care.qumulo.com/hc/en-us/articles/360011328533-SMB-Share-Permissions
		https://care.qumulo.com/hc/en-us/articles/360005375333-Hide-an-SMB-Share
		https://care.qumulo.com/hc/en-us/articles/360041155254-SMB-Host-Restrictions
    #>
	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Name")][string]$Name
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

		Write-Debug ($global:Credentials|ConvertTo-Json -Depth 10)

		$TokenHeader = @{
			Authorization = "Bearer $bearerToken"
		}

		# API url definition
		if ($Id) {
			$url = "/v2/smb/shares/$Id"
		}
		elseif ($Name) {
			$url = "/v2/smb/shares/$Name"
		}

		#API call run
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

function Add-QQSMBSharePermission {
<#
	.SYNOPSIS
		Add new SMB share permissions
	.DESCRIPTION
		Add new SMB share permission
	.PARAMETER Id [ID]
		The SMB share ID
	.PARAMETER Name [NAME] 
		The SMB share name
    .PARAMETER Type [Allowed|Denied]
		SMB Share permission type
	.PARAMETER Rights [None|Read,Write,Change_permissions|All]
		SMB Share permission rights. 
    .PARAMETER Trustee [TRUSTEE]
		Trustees. e.g. Everyone, uid:1000, gid:1001, sid:S-1-5-2-3-4, or auth_id:500
	.EXAMPLE
		Add-QQSMBSharePermissions -Name [NAME] | -Id [ID]
			-Type [Allowed|Denied]
			-Rights [None|Read,Write,Change_permissions|All]
			-Trustee [TRUSTEE]
			[-Json]
		#>
	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Name")][string]$Name,
		[Parameter(Mandatory = $True)][string]$Trustee,
		[Parameter(Mandatory = $True)][ValidateSet("Allowed","Denied")] [string]$Type,
		[Parameter(Mandatory = $True)][ValidateSet("None","Read","Write","Change_permissions","All")] [array]$Rights,
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

		Write-Debug ($global:Credentials|ConvertTo-Json -Depth 10)

		$TokenHeader = @{
			Authorization = "Bearer $bearerToken"
		}

		# Share Name -> ID conversion
		if (!$Id) {
			$url = "/v2/smb/shares/$Name"
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
			$Id = $response.id

			Write-Debug ($response| ConvertTo-Json -Depth 10)
		}

	
		try {
			# API url definition
			$url = "/v2/smb/shares/" + $Id + "?allow-fs-path-create=false"
	
			# API Request body
			$permissions = $response.permissions
			
			# Trustee identification
			if ($trustee.Contains(':'))
			{
				$trusteeArray = $trustee.Split(":")
				$trusteeHash = @{ $trusteeArray[0] = $trusteeArray[1] }
			}
			else {
				$trusteeHash = @{ name = $trustee }
			}

			$newRights = @()
			foreach ($right in $Rights) {
				$newRights += $right.ToUpper()
			}
			$permissions += (
				@{
					type = $Type.ToUpper()
					trustee = $trusteeHash
					rights = $newRights
				}
			)

			$body = @{
				"permissions" = $permissions
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
	catch {
		$_.Exception.Response
	}
}

function Remove-QQSMBSharePermission {
<#
	.SYNOPSIS
		Remove matched SMB share permissions
	.DESCRIPTION
		Remove matched SMB share permissions
	.PARAMETER Id [ID]
		The SMB share ID
	.PARAMETER Name [NAME] 
		The SMB share name
    .PARAMETER Type [Allowed|Denied]
		SMB Share permission type
	.PARAMETER Rights [None|Read,Write,Change_permissions|All]
		SMB Share permission rights. 
    .PARAMETER Trustee [TRUSTEE]
		Trustees. e.g. Everyone, uid:1000, gid:1001, sid:S-1-5-2-3-4, or auth_id:500
	.EXAMPLE
		Remove-QQSMBSharePermissions -Name [NAME] | -Id [ID]
			-Type [Allowed|Denied]
			-Rights [None|Read,Write,Change_permissions|All]
			-Trustee [TRUSTEE]
			[-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/360000722428-Create-an-SMB-Share
		https://care.qumulo.com/hc/en-us/articles/115013237727-QQ-CLI-SMB-Shares
		https://care.qumulo.com/hc/en-us/articles/360011328533-SMB-Share-Permissions
		https://care.qumulo.com/hc/en-us/articles/360005375333-Hide-an-SMB-Share
		https://care.qumulo.com/hc/en-us/articles/360041155254-SMB-Host-Restrictions
		#>
	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Name")][string]$Name,
		[Parameter(Mandatory = $True)][string]$Trustee,
		[Parameter(Mandatory = $True)][ValidateSet("Allowed","Denied")] [string]$Type,
		[Parameter(Mandatory = $True)][ValidateSet("None","Read","Write","Change_permissions","All")] [array]$Rights,
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

		Write-Debug ($global:Credentials|ConvertTo-Json -Depth 10)

		$TokenHeader = @{
			Authorization = "Bearer $bearerToken"
		}

		# Share Name -> ID conversion
		if (!$Id) {
			$url = "/v2/smb/shares/$Name"
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
			$Id = $response.id

			Write-Debug ($response| ConvertTo-Json -Depth 10)
		}

		try {
			# API url definition
			$url = "/v2/smb/shares/" + $Id + "?allow-fs-path-create=false"

			# API Request body	
			$newPermissions = @()
			$permissions = $response.permissions

			foreach ($permission in $permissions) {
				# Trustee identification
				if ($Trustee.Contains(':'))
				{
					if ($permission.trustee.$(($trustee -split '\:')[0]) -eq $(($trustee -split '\:')[1])) {
						$trusteeCheck = $true
					}
				}
				else {
					if ($permission.trustee.Name -eq $trustee) {
						$trusteeCheck = $true
					}
					else{
						$trusteeCheck = $false
					}
				}

				$updatedRights = @()
				foreach ($right in $Rights) {
					$updatedRights += $right.ToUpper()
				}

				$compareRights = Compare-Object $permission.rights $updatedRights
				if (!$compareRights) {
					$rightsCheck = $true
				}
				else{
					$rightsCheck = $false
				} 

				if ($permission.type -eq $Type.ToUpper()) {
					$typeCheck = $true
				}
				else{
					$typeCheck = $false
				}

				Write-Verbose($trusteeCheck| ConvertTo-Json -Depth 10)
				if (($trusteeCheck -ne $true) -or ($rightsCheck -ne $true) -or ($typeCheck -ne $true))
				{
					$newPermissions += $permission
				}
			}
			
			
			# API request body	
			$body = @{
				"permissions" = $newPermissions
			}

			Write-Debug ($body | ConvertTo-Json -Depth 10)

			# API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
				
				# Response
				$comparePermissions = Compare-Object  $permissions $newPermissions
				if($comparePermissions)
				{
					if ($Json) {
						return @($response) | ConvertTo-Json -Depth 10
					}
					else {
						return $response
					}
				}
				else{
					Write-Host "No matched entry!"
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
	catch {
		$_.Exception.Response
	}

}

function Get-QQSMBSettings {
<#
	.SYNOPSIS
		Get SMB settings
	.DESCRIPTION
		Get SMB settings
	.EXAMPLE
		Get-QQSMBSettings [-Json]
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
			if (!$global:Credentials.BearerToken.StartsWith("session-v1")) {
				Login-QQCluster
			}
		}

		$bearerToken = $global:Credentials.BearerToken
		$clusterName = $global:Credentials.ClusterName
		$portNumber = $global:Credentials.PortNumber

		Write-Debug ($global:Credentials|ConvertTo-Json -Depth 10)

		$TokenHeader = @{
			Authorization = "Bearer $bearerToken"
		}

		# API url definition
		$url = "/v1/smb/settings"

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


function Modify-QQSMBSettings {
<#
	.SYNOPSIS
		Set SMB server settings
	.DESCRIPTION
		Partially set settings for the SMB Server.
	.PARAMETER 	EncryptionMode {none,preferred,required}
		Server encryption mode to set
	.PARAMETER SupportedDialects dialect_1 [dialect_2 ...]
		Space separated set of SMB dialects to allow clients to negotiate. Choose from the following:
			smb2_dialect_2_002, smb2_dialect_2_1,
			smb2_dialect_3_0, smb2_dialect_3_11, 
			or use -SupportedDialects ALL to allow all supported dialects.
	.PARAMETER HideSharesFromUnauthorizedHosts {true,false}
		Share listing will omit shares that the requesting host is not authorized to connect to.
	.PARAMETER HideSharesFromUnauthorizedUsers {true,false}
		Share listing will omit shares that the requesting user is not authorized to connect to. Caution: clients that are not configured for passwordless authentication typically list shares using guest privileges; this option will typically hide all shares from such clients.
	.PARAMETER SnapshotDirectoryMode {visible,hidden,disabled}
		If "visible", a special .snapshot directory will appear in directory listings at the root of shares, and be accessible by name in any directory. 
		If "hidden", the .snapshot directory will not appear in directory listings, but will still be accessible by name. 
		If "disabled", .snapshot directories will not be accessible, and snapshots will only be available via e.g. the Restore Previous Versions dialog on Windows.
	.PARAMETER BypassTraverseChecking {$true,$false}
		Bypass traverse checking for all users and all directories. In other words, a user trying to access /foo/bar who has permissions to bar but no permissions to foo can still access bar. Users still need permissions on foo to see the contents of that directory.
	.PARAMETER SigningRequired {true,false}
		Require that messages must be signed if the user is not guest. Applies to all SMB shares.
	.EXAMPLE
		Modify-QQSMBSettings [-Json]
			-EncryptionMode {none,preferred,required}
					Server encryption mode to set
			-SupportedDialects dialect_1 [dialect_2 ...]
			-HideSharesFromUnauthorizedHosts {true,false}
			-HideSharesFromUnauthorizedUsers {true,false}
			-SnapshotDirectoryMode {visible,hidden,disabled}
			-BypassTraverseChecking {true,false}
			-SigningRequired {true,false}
		.LINK
			https://care.qumulo.com/hc/en-us/articles/360000722428-Create-an-SMB-Share
			https://care.qumulo.com/hc/en-us/articles/115013237727-QQ-CLI-SMB-Shares
			https://care.qumulo.com/hc/en-us/articles/360011328533-SMB-Share-Permissions
			https://care.qumulo.com/hc/en-us/articles/360005375333-Hide-an-SMB-Share
			https://care.qumulo.com/hc/en-us/articles/360041155254-SMB-Host-Restrictions
	#>
	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $False)][ValidateSet("none","preferred","required")] [string]$EncryptionMode,
		[Parameter(Mandatory = $False)] [bool]$HideSharesFromUnauthorizedHosts,
		[Parameter(Mandatory = $False)] [bool]$HideSharesFromUnauthorizedUsers,
		[Parameter(Mandatory = $False)] [bool]$BypassTraverseChecking,
		[Parameter(Mandatory = $False)] [bool]$SigningRequired,
		[Parameter(Mandatory = $False)][ValidateSet("visible","hidden","disabled")] [string]$SnapshotDirectoryMode,
		[Parameter(Mandatory = $False)][ValidateSet("smb2_dialect_2_002","smb2_dialect_2_1","smb2_dialect_3_0","smb2_dialect_3_11","All")] [array]$SupportedDialects
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

		Write-Debug ($global:Credentials|ConvertTo-Json -Depth 10)

		$TokenHeader = @{
			Authorization = "Bearer $bearerToken"
		}

		# API Request body
		$body = @{}

		if ($EncryptionMode) {
			$body += @{
				"session_encryption" = $EncryptionMode.ToUpper() }
		}

		if ($HideSharesFromUnauthorizedHosts) {
			$body += @{
				"hide_shares_from_unauthorized_hosts" = $HideSharesFromUnauthorizedHosts
			}

		}

		if ($HideSharesFromUnauthorizedUsers) {
			$body += @{
				"hide_shares_from_unauthorized_users" = $HideSharesFromUnauthorizedUsers
			}
		}

		if ($BypassTraverseChecking) {
			$body += @{
				bypass_traverse_checking = $BypassTraverseChecking
			}
		}

		if ($SigningRequired) {
			$body += @{
				"signing_required" = $SigningRequired
			}
		}

		if ($SnapshotDirectoryMode) {
			$body += @{
				"snapshot_directory_mode" = $SnapshotDirectoryMode.ToUpper()
			}
		}

		if ($SupportedDialects) {
			if ($SupportedDialects -eq "ALL") {
				$body += @{
					"supported_dialects" = @(
						"SMB2_DIALECT_2_002",
						"SMB2_DIALECT_2_1",
						"SMB2_DIALECT_3_0",
						"SMB2_DIALECT_3_11"
					)
				}
			}
			else {
				$body += @{
					"supported_dialects" = $SupportedDialects
				}
			}
		}

		# API url definition
		$url = "/v1/smb/settings"

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
function List-QQSMBFileHandles {
<#
	.SYNOPSIS
		List SMB open file handles.
	.DESCRIPTION
		List SMB open file handles
	.PARAMETER Path [PATH]
		Path to file.
	.PARAMETER PageSize [PAGE_SIZE]
		Max files to return per request
	.PARAMETER ResolvePaths
		Returns the primary path of the opened file
	
	.EXAMPLE
		List-QQSMBFileHandles -Path PATH -PageSize 10 -ResolvePaths [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/360044728593-Close-an-Open-SMB-File-via-QQ-CLI
	#>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)][string]$Path,
		[Parameter(Mandatory = $False)][string]$FileNumber,
		[Parameter(Mandatory = $False)][string]$PageSize,
		[Parameter(Mandatory = $False)] [bool]$ResolvePaths=$False,
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
		if($Path){
			$url = "/v1/smb/files/?file_number=$id&"
		}
		else {
			if($FileNumber){
				$url = "/v1/smb/files/?file_number=$FileNumber&"
			}
			else {
				$url = "/v1/smb/files/?"
			}
		}	
		if($ResolvePaths){
			$url += "resolve_paths=True"
		}
		else {
			$url += "resolve_path=False"
		}

		if($PageSize) {
			$url += "&limit=$PageSize"
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

function Close-QQSMBFileHandles {
	<#
		.SYNOPSIS
			Force close a specified SMB file handle
		.DESCRIPTION
			Force close a specified SMB file handle

			NOTE: This will prevent the client from sending any new requests for
			this file handle, releasing all locks and forcing the client to reopen
			the file. The client will not be given the opportunity to flush cached
			writes. Proceed with caution!
		.PARAMETER Location [LOCATION]
			The location of the file handle to close as returned from List-QQSMBFileHandles
		.EXAMPLE
			Close-QQSMBFileHandles -Location [LOCATION]
		.LINK
			https://care.qumulo.com/hc/en-us/articles/360044728593-Close-an-Open-SMB-File-via-QQ-CLI
		#>
	
		# CmdletBinding parameters
		[CmdletBinding()]
		param(
			[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()] [string]$Location,
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
	
			# API Request body
			$body = @()
			$body += ( 
					@{
					'file_number'=0
					'handle_info'= @{
						'owner'='0'
						'access_mask'=@('MS_ACCESS_FILE_READ_ATTRIBUTES') 
						'version'= 0
						'location'=$Location
						'num_byte_range_locks'=0
					}
				}
			)

			$bodyJson = $body | ConvertTo-Json -Depth 10

			Write-Debug($body| ConvertTo-Json -Depth 10)

			# API url definition
			$url = "/v1/smb/files/close"

			# API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ("["+$bodyJson+"]") -TimeoutSec 60 -ErrorAction:Stop

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

		else {
			return ("Missing parameter!")
		}
	}
	catch {
		$_.Exception.Response
	}
}
	
function List-QQSMBSessions {
<#
	.SYNOPSIS
		List SMB open sessions
	.DESCRIPTION
		List SMB open sessions
	.PARAMETER Identity [IDENTITY]
		List only sessions matching this user's identity in the form of: [1] A name or a SID optionally qualified with a domain prefix (e.g "local:name", "S-1-1-0", "name", "world:Everyone",
        "ldap_user:name", or "ad:name"), or [2] An ID type (e.g. "uid:1001", "auth_id:513", "SID:S-1-1-0").
	.PARAMETER PageSize [PAGE_SIZE]
		Max sessions to return per request
	
	.EXAMPLE
		List-QQSMBSessions -Identity ab:qumulouser -PageSize 10 [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/360046854394-Close-an-Open-SMB-Session
	#>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)][string]$Identity,
		[Parameter(Mandatory = $False)][string]$PageSize,
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
		$url = "/v1/smb/sessions/"


		if(($PageSize) -And ($Identity)){
			$htmlIdentity = ([uri]::EscapeDataString($Identity))
			$url += "?limit=$PageSize&?identity=$htmlIdentity"
		}
		else{
			if($PageSize) {
				$url += "?limit=$PageSize"
			}

			if($Identity){
				$htmlIdentity = ([uri]::EscapeDataString($Identity))
				$url += "?identity=$htmlIdentity"
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

function Close-QQSMBSessions {
	<#
		.SYNOPSIS
			Force close SMB sessions matching one or more of a set of filters.

		.DESCRIPTION
			Force close SMB sessions matching one or more of a set of filters.

			NOTE: This will prevent the client from sending any new requests for
			this session, releasing all locks and forcing the client to
			reauthenticate. The client will not be given the opportunity to flush
			cached writes. Proceed with caution!
		.PARAMETER Location [LOCATION]
			The location of the file handle to close as returned from List-QQSMBSessions
		.PARAMETER Identity [IDENTITY]  
			Close only sessions matching this user's identity in the form of: [1] A name or a SID optionally qualified with a domain prefix (e.g "local:name", "S-1-1-0", "name", 
			"world:Everyone", "ldap_user:name", or "ad:name"), or [2] An ID type (e.g. "uid:1001","auth_id:513", "SID:S-1-1-0").
		.PARAMETER Ip [IP]              
			Close only sessions originating from this ip.
		.EXAMPLE
			Close-QQSMBSessions -Location [LOCATION]
		.LINK
			https://care.qumulo.com/hc/en-us/articles/360046854394-Close-an-Open-SMB-Session
		#>
	
		# CmdletBinding parameters
		[CmdletBinding()]
		param(
			[Parameter(Mandatory = $False)][string]$Location,
			[Parameter(Mandatory = $False)][string]$Identity,
			[Parameter(Mandatory = $False)][string]$Ip,
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


			$url = "/v1/smb/sessions/"
			if($Identity){
				$htmlIdentity = ([uri]::EscapeDataString($Identity))
				$url += "?identity=$htmlIdentity"
			}
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
				$sessions = $response.session_infos
			}
			catch {
				$_.Exception.Response
			}
	
			# API Request body
			 
			$matchedSessions1 = @()
			$matchedSessions2 = @()
			$matchedSessions3 = @()

			foreach ($session in $sessions){
				if($Ip){
					if ($session.originator -eq $Ip) {
						$matchedSessions1 += $session
					}
				}
				else{
					$matchedSessions1 += $session
				}    
			}

			foreach ($matchedSession1 in $matchedSessions1){
				if($Location){
					if ($matchedSession1.location -eq $Location) {
						$matchedSessions2 += $matchedSession1
					}
				}
				else{
					$matchedSessions2 += $matchedSession1    
				}
			}
			# Write-Debug("Matched Sessions2:")
			# Write-Debug($matchedSessions2 | ConvertTo-Json -Depth 10)

			foreach ($matchedSession2 in $matchedSessions2){
				if($Identity){
					$userCheck = $matchedSession2.user
					if ($userCheck.ContainsValue($Identity)){
						$matchedSessions3 += $matchedSession2
						Write-Debug($Identity)
					}
				}
				else{
					# $userCheck = $matchedSession2.user
					# Write-Debug($userCheck | ConvertTo-Json -Depth 10)
					$matchedSessions3 += $matchedSession2 
				}
			} 
			# Write-Debug("Matched Sessions3:")
			# Write-Debug($matchedSessions3 | ConvertTo-Json -Depth 10)

			
			$body = $matchedSessions3
			
			$bodyJson = $body | ConvertTo-Json -Depth 10
			Write-Debug($body | ConvertTo-Json -Depth 10)

			# API url definition
			$url = "/v1/smb/sessions/close"

			# API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ("["+$bodyJson+"]") -TimeoutSec 60 -ErrorAction:Stop

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

		else {
			return ("Missing parameter!")
		}
	}
	catch {
		$_.Exception.Response
	}
}
