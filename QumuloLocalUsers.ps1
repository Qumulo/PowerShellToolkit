<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloLocalUsers.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo local users configurations and operations
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
function List-QQLocalUsers {
<#
    .SYNOPSIS
        List all users
    .DESCRIPTION
       List all users
    .EXAMPLE
        Get-QQLocalUsers [-Json]
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
		$url = "/v1/users/"

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

function Get-QQLocalUser {
<#
    .SYNOPSIS
        Get local user details.
    .DESCRIPTION
        Get local user details.
    .EXAMPLE
        Get-QQLocalUser -Id [ID] [-Json]
        Get-QQLocalUser -Name [USERNAME] [-Json]
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
			$url = "/v1/users/"

			# API call run
			try {
				$users = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

				foreach ($user in $users) {
					if ($Name -eq $user.Name) {
						$Id = $user.id
					}
				}
			}
			catch {
				$_.Exception.Response
			}
		}
		# API url definition
		$url = "/v1/users/$Id"

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

function Get-QQLocalUserGroups {
<#
    .SYNOPSIS
        Get a local user's group details.
    .DESCRIPTION
        Get a local user's group details.
    .EXAMPLE
        Get-QQLocalUserGroups -Id [ID] [-Json]
        Get-QQLocalUserGroups-Name [USERNAME] [-Json]
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
			$url = "/v1/users/"

			# API call run
			try {
				$users = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

				foreach ($user in $users) {
					if ($Name -eq $user.Name) {
						$Id = $user.id
					}
				}
			}
			catch {
				$_.Exception.Response
			}
		}
		# API url definition
		$url = "/v1/users/$Id/groups/"

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

function Add-QQLocalUser {
<#
    .SYNOPSIS
        Add a new user
    .DESCRIPTION
        Add a new user
    .PARAMETER Name [USERNAME]
        New user's name (windows style)
    .PARAMETER PrimaryGroup [PRIMARY_GROUP]
        name or id of primary group (default is Users)
    .PARAMETER Uid [UID]
        optional NFS uid
    .PARAMETER HomeDirectory [HOME_DIR]
        optional home directory
    .PARAMETER Password [PASSWORD]
        Set user password; reads password from terminal if omitted
    .EXAMPLE
        Add-QQLocalUser -Name [USERNAME] [-Json]
    #>

	# CmdletBinding parameters
	[CmdletBinding(DefaultParameterSetName = 'Secret')]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $True)] [string]$Name,
		[Parameter(Mandatory = $False)] [string]$PrimaryGroup = "Users",
		[Parameter(Mandatory = $False)] [string]$Uid,
		[Parameter(Mandatory = $True,ParameterSetName = 'Secret')] [Security.SecureString]${ClusterPassword},
		[Parameter(Mandatory = $True,ParameterSetName = 'Plain')] [string]$Password,
		[Parameter(Mandatory = $False)] [string]$HomeDirectory
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

		if ($PrimaryGroup -eq "Users") {
			$Gid = '0'
		}
		else {
			# API url definition
			$url = "/v1/groups/"

			# API call run
			try {
				$gids = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

				foreach ($gid_details in $gids) {
					if ($gid_details.Name -eq $PrimaryGroup) {
						$gid = $gid_details.id
					}
				}

			}
			catch {
				$_.Exception.Response
			}
		}

		# API Request Body
		$body = @{
			'name' = $Name
			'password' = ConvertFrom-SecureString -SecureString $SecurePassword -AsPlainText
			'uid' = $Uid
			'primary_group' = $Gid
			'home_directory' = $HomeDirectory
		}

		Write-Debug ($body | ConvertTo-Json -Depth 10)

		# API url definition
		$url = "/v1/users/"

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


function Delete-QQLocalUser {
<#
    .SYNOPSIS
        Delete a new user
    .DESCRIPTION
        Delete a new user
    .PARAMETER Name [USERNAME]
        Name of user to delete
    .PARAMETER Id [ID]
        ID of user to delete
    .EXAMPLE
        Delete-QQLocalUser -Name [USERNAME] 
        Delete-QQLocalUser -Id [ID] 
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
			$url = "/v1/users/"

			# API call run
			try {
				$users = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

				foreach ($user in $users) {
					if ($user.Name -eq $Name) {
						$Id = $user.id
					}
				}

			}
			catch {
				$_.Exception.Response
			}
		}


		# API url definition
		$url = "/v1/users/$Id"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
			# Response
			return "User was deleted succesfully."
		}
		catch {
			$_.Exception.Response
		}
	}
	catch {
		$_.Exception.Response
	}
}


function Set-QQUserPassword {
<#
        .SYNOPSIS
            Set a user's password
        .DESCRIPTION
            Set a user's password
        .PARAMETER Name [USERNAME]
            Name of user to modify
        .PARAMETER Id [ID]
            ID of user to modify
        .PARAMETER Password [PASSWORD]
            New user password
        .EXAMPLE
            Set-QQSetUserPassword -Name [USERNAME] -Password [PASSWORD]
            Set-QQSetUSerPassword -Id [ID] -Password [PASSWORD]
        #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $True,ParameterSetName = 'Name')] [string]$Name,
		[Parameter(Mandatory = $True,ParameterSetName = 'Id')] [string]$Id,
		[Parameter(Mandatory = $True)] [string]$Password
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
			$url = "/v1/users/"

			# API call run
			try {
				$users = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

				foreach ($user in $users) {
					if ($user.Name -eq $Name) {
						$Id = $user.id
					}
				}

			}
			catch {
				$_.Exception.Response
			}
		}

		# API body
		$body = @{ 'new_password' = $Password }

		# API url definition
		$url = "/v1/users/$Id/setpassword"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
			# Response
			return "User password was changed succesfully."
		}
		catch {
			$_.Exception.Response
		}
	}
	catch {
		$_.Exception.Response
	}
}
