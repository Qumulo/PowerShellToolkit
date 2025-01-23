<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloSession.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo session configurations and operations
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
function Login-QQCluster {
	<#
	.SYNOPSIS
		Log in to Qumulo to get REST credentials
	.DESCRIPTION
		Authenticate the user using either an access token or a username & password.
	.PARAMETER clusterName
		DNS name or one of the IP addresses of the Qumulo cluster
	.PARAMETER portNumber
		Port number for REST connection. Default is 8000
	.PARAMETER userName
		User name for login. 
	.PARAMETER password
		Password of the user. 
	.PARAMETER AccessToken
		Pre-existing bearer token for authentication.
	.EXAMPLE
		Login-QQCluster -clusterName qumulocluster.local -portNumber 8000 -userName USERNAME -Password PASSWORD
		Login-QQCluster -clusterName qumulocluster.local -portNumber 8000 -AccessToken "your_access_token"
	.LINK
		https://care.qumulo.com/hc/en-us/articles/360004600994-Authentication-with-Qumulo-s-REST-API#use-the-bearer-token-0-4
#>

	[CmdletBinding(DefaultParameterSetName = 'Secret')]
	param(
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Alias("c")] [string]$clusterName,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][Alias("p")] [int]$portNumber = 8000,
		[Parameter(Mandatory = $False, ParameterSetName = 'Token')][Alias("token")] [string]$AccessToken,
		[Parameter(Mandatory = $True, ParameterSetName = 'Secret')][Alias("u")] [string]$userName,
		[Parameter(Mandatory = $True, ParameterSetName = 'Secret')] [Security.SecureString]${ClusterPassword},
		[Parameter(Mandatory = $True, ParameterSetName = 'Plain')][Alias("pass")] [string]$Password
	)

	if ($SkipCertificateCheck -eq 'true') {
		$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
	}

	if ($AccessToken) {
		# Use the provided AccessToken directly
		$global:Credentials = @{
			ClusterName = $ClusterName
			PortNumber = $PortNumber
			BearerToken = $AccessToken
		}
		Write-Output "Authenticated using AccessToken."
		return
	}

	# Password handling
	if ($Password) {
		$SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
	} else {
		$SecurePassword = ${ClusterPassword}
	}

	# Login via username & password if AccessToken is not provided
	$Body = @{
		'username' = $UserName
		'password' = ConvertFrom-SecureString -SecureString $SecurePassword -AsPlainText
	}

	$Url = "/v1/session/login"

	try {
		$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${ClusterName}:$PortNumber$Url" -Body ($Body | ConvertTo-Json -Depth 10) -ContentType "application/json" -TimeoutSec 60 -ErrorAction Stop

		# Store credentials globally
		$global:Credentials = @{
			ClusterName = $ClusterName
			PortNumber = $PortNumber
			BearerToken = $response.bearer_token
		}

		Write-Output "Authenticated using username and password."
		return
	}
	catch {
		Write-Error "Login failed: $($_.Exception.Response)"
	}
}
function List-QQCurrentUser {
<#
    .SYNOPSIS
        Get information on the current user
    .DESCRIPTION
        Retrieve information about the currently logged in user.
    .EXAMPLE
        List-QQCurrentUser [-Json]
    #>

	# CmdletBinding parameters. 
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$json
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
		$url = "/v1/session/who-am-i"

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Outputs
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

function List-QQCurrentRoles {
<#
    .SYNOPSIS
        List all of the roles.
    .DESCRIPTION
        Retrieve a list of all the roles assigned to the current user, including those assigned to a group to which the current user belongs.
    .EXAMPLE
        List-QQCurrentRoles [-Json]
    .LINK
		https://care.qumulo.com/hc/en-us/articles/360036591633-Role-Based-Access-Control-RBAC-with-Qumulo-Core
    #>

	# CmdletBinding parameters. 
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
		$url = "/v1/session/roles"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Outputs
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

function List-QQAllPrivileges {
<#
	.SYNOPSIS
		Get information about all privileges.
	.DESCRIPTION
		Get information about all privileges.
	.EXAMPLE
		List-QQAllPrivileges [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/360036591633-Role-Based-Access-Control-RBAC-with-Qumulo-Core
	#>

	# CmdletBinding parameters. 
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
		$url = "/v1/auth/privileges/"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Outputs
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

