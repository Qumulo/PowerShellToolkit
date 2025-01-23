<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloLocalGroups.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo local groups configurations and operations
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
function List-QQLocalGroups {
<#
    .SYNOPSIS
        List all groups
    .DESCRIPTION
       List all groups
    .EXAMPLE
        Get-QQLocalGroups [-Json]
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
		$url = "/v1/groups/"

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

function Get-QQLocalGroup {
<#
    .SYNOPSIS
        Get a local group details.
    .DESCRIPTION
        Get a local group details.
    .EXAMPLE
        Get-QQLocalGroup -Id [ID] [-Json]
        Get-QQLocalGroup -Name [USERNAME] [-Json]
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Name")][ValidateNotNullOrEmpty()] [string]$Name,
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

		if ($Name) {
			# API url definition
			$url = "/v1/groups/"

			# API call run
			try {
				$groups = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

				foreach ($group in $groups) {
					if ($Name -eq $group.Name) {
						$Id = $group.id
					}
				}
			}
			catch {
				$_.Exception.Response
			}
		}
		# API url definition
		$url = "/v1/groups/$Id"

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

function Get-QQGroupMembers {
<#
    .SYNOPSIS
        Get a local group's members.
    .DESCRIPTION
        Get a local group's members.
    .EXAMPLE
        Get-QQGroupMembers -Id [ID] [-Json]
        Get-QQGroupMembers-Name [USERNAME] [-Json]
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
		[Parameter(Mandatory = $True,ParameterSetName = "Name")][ValidateNotNullOrEmpty()] [string]$Name,
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

		if ($Name) {
			# API url definition
			$url = "/v1/groups/"

			# API call run
			try {
				$groups = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

				foreach ($group in $groups) {
					if ($Name -eq $group.Name) {
						$Id = $group.id
					}
				}
			}
			catch {
				$_.Exception.Response
			}
		}
		# API url definition
		$url = "/v1/groups/$Id/members/"

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

function Add-QQLocalGroup {
<#
    .SYNOPSIS
        Add a new group
    .DESCRIPTION
        Add a new group
    .PARAMETER Name [GROUPNAME]
        New group's name (windows style)
    .PARAMETER Gid [GID]
        optional NFS gid
    .EXAMPLE
        Add-QQLocalGroup -Name [GROUPNAME] [-Json]
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $True)] [string]$Name,
		[Parameter(Mandatory = $False)] [string]$Gid
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

		# Password parameter checks and conversion for the required formats. 
		if ($Password) {
			$SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
		}
		else {
			$SecurePassword = ${ClusterPassword}
		}

		# API Request Body
		$body = @{
			'name' = $Name
			'gid' = $gid
		}

		Write-Debug ($body | ConvertTo-Json -Depth 10)

		# API url definition
		$url = "/v1/groups/"

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


function Delete-QQLocalGroup {
<#
    .SYNOPSIS
        Delete a new group
    .DESCRIPTION
        Delete a new group
    .PARAMETER Name [GROUPNAME]
        Name of group to delete
    .PARAMETER Id [ID]
        ID of group to delete
    .EXAMPLE
        Delete-QQLocalGroup -Name [USERNAME] 
        Delete-QQLocalGroup -Id [ID] 
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $True,ParameterSetName = 'Name')] [string]$Name,
		[Parameter(Mandatory = $True,ParameterSetName = 'Id')] [string]$Id
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

		# Password parameter checks and conversion for the required formats. 
		if (!$Id) {
			# API url definition
			$url = "/v1/groups/"

			# API call run
			try {
				$groups = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

				foreach ($group in $groups) {
					if ($group.Name -eq $Name) {
						$Id = $group.id
					}
				}

			}
			catch {
				$_.Exception.Response
			}
		}


		# API url definition
		$url = "/v1/groups/$Id"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
			# Response
			return "Group was deleted succesfully."
		}
		catch {
			$_.Exception.Response
		}
	}
	catch {
		$_.Exception.Response
	}
}


function Modify-QQLocalGroup {
<#
        .SYNOPSIS
            Modify a group
        .DESCRIPTION
            Modify a group
        .PARAMETER Name [GROUPNAME]
            Name of user to modify
        .PARAMETER Id [ID]
            ID of user to modify
        .PARAMETER NewName [GROUPNAME]
            Change group's name
        .PARAMETER Gid [GID]
            Change the user's NFS gid (or specify "none" to remove)
        .EXAMPLE
            Modify-QQLocalGroup -Name [GROUPNAME] -NewName [GROUPNAME] -Gid [GID]
            Modify-QQLocalGroup -Id [ID] -NewName [GROUPNAME] -Gid [GID]
        #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $False)] [string]$NewName,
		[Parameter(Mandatory = $False)] [string]$Gid,
		[Parameter(Mandatory = $True,ParameterSetName = 'Name')] [string]$Name,
		[Parameter(Mandatory = $True,ParameterSetName = 'Id')] [string]$Id
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

		# Password parameter checks and conversion for the required formats. 
		if (!$Id) {
			# API url definition
			$url = "/v1/groups/"

			# API call run
			try {
				$groups = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

				foreach ($group in $groups) {
					if ($group.Name -eq $Name) {
						$Id = $group.id
					}
				}

			}
			catch {
				$_.Exception.Response
			}
		}
		else {
			# API url definition
			$url = "/v1/groups/"

			# API call run
			try {
				$groups = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

				foreach ($group in $groups) {
					if ($group.id -eq $Id) {
						$Name = $group.Name
					}
				}

			}
			catch {
				$_.Exception.Response
			}
		}

		if (!$NewName) {
			$NewName = $Name
		}

		if ($Gid -eq "none") {
			$Gid = ''
		}

		# API request body
		$body = @{
			'id' = $Id
			'name' = $NewName
			'gid' = $Gid
		}

		Write-Debug ($body | ConvertTo-Json -Depth 10)

		# API url definition
		$url = "/v1/groups/$Id"

		# API call run
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
