<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloAccessToken.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo Audit log configurations and operations
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
function List-QQAccessTokens {
<#
    .SYNOPSIS
        List metadata for all access tokens
    .DESCRIPTION
        List all access tokens for the cluster.
    .PARAMETER User [USER]
        Show access tokens belonging to a specific user. Use an auth_id, SID, or name
        optionally qualified with a domain prefix (e.g "local:name", "ad:name",
        "AD\name") or an ID type (e.g. "auth_id:513", "SID:S-1-1-0"). Groups are not
        supported for access tokens, must be a user.
    .EXAMPLE
        List-QQAccessTokens [-Json]
        List-QQAccessTokens -User local:berat
    .LINK
        https://docs.qumulo.com/administrator-guide/external-services/using-access-tokens.html
    #>

	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [string]$User,
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
		$url = "/v1/auth/access-tokens/"

		if ($User) {
			$url += "?user=$User"
		}

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

function Get-QQAccessToken {
<#
    .SYNOPSIS
        Get metadata for the specified access token
    .DESCRIPTION
        Get metadata about the specified access token.
    .PARAMETER Id [Token ID]
        The unique ID of the access token
    .EXAMPLE
        Get-QQAccessToken -Id [Token ID] [-Json]
    .LINK
        https://docs.qumulo.com/administrator-guide/external-services/using-access-tokens.html
    #>

	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [string]$Id,
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
		$url = "/v1/auth/access-tokens/$Id"

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
function Create-QQAccessToken {
<#
    .SYNOPSIS
        Create a long-lived access token
    .DESCRIPTION
        Create an access token for the specified user.
    .PARAMETER Identifier [AUTH_ID, SID, USERNAME]
        An auth_id, SID, or name optionally qualified with a domain prefix
        (e.g "local:name", "ad:name", "AD\name") or an ID type (e.g.
        "auth_id:513", "SID:S-1-1-0"). Groups are not supported for access
        tokens, must be a user.
    .PARAMETER ExpirationTime [EXPIRATION_TIME]
        The expiration time of the access token. After this time, the token
        will no longer be usable for authentication. For example, "2024-01-20T12:00:00", with times interpreted in
        UTC timezone.
    .EXAMPLE
        Create-QQAccessToken -Identifier [AUTH_ID, SID, USERNAME] [-Json]
        Create-QQAccessToken -Identifier [AUTH_ID, SID, USERNAME] -ExpirationTime 1/20/2024" [-Json]
    #>

	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Identifier,
		[Parameter(Mandatory = $False)] [string]$ExpirationTime,
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

		# API Request Body


		if ($Identifier.Contains(":")) {
			$splittedUsername = $Identifier.Split(":")
			$domain = $splittedUsername[0]
			$name = $splittedUsername[1]
			if (($domain -eq "auth_id") -or ($domain -eq "sid")) {
				$user = @{
					$domain = $name
				}
			}
			else {
				$user = @{
					'domain' = $domain.ToUpper()
					'name' = $name
				}
			}
		}
		elseif ($Identifier.Contains("\")) {
			$splittedUsername = $Identifier.Split("\")
			$domain = $splittedUsername[0].ToUpper()
			$name = $splittedUsername[1]
		}

		if ($ExpirationTime) {
			try
			{
				$parsedTime = ([datetime]::ParseExact($ExpirationTime,"yyyy-MM-ddTHH:mm:ss",[System.Globalization.CultureInfo]::InvariantCulture))
				$longExpirationTime = "$expirationTime+00:00"
			}
			catch {
				return "Wrong time format.For example, '2024-01-20T12:00:00', with times interpreted in UTC timezone."
				break
			}

			$body = @{
				'user' = $user
				'expiration_time' = $longExpirationTime
			}
		}
		else {
			$body = @{
				'user' = $user
			}
		}
		Write-Debug ($body | ConvertTo-Json -Depth 10)

		# API url definition
		$url = "/v1/auth/access-tokens/"

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

function Modify-QQAccessToken {
<#
        .SYNOPSIS
            Modify the specified access token
        .DESCRIPTION
            Modify metadata for the specified access token.
        .PARAMETER Id [ACCESS_TOKEN_ID]
            The unique ID of the access token to be modified.
        .PARAMETER ExpirationTime [EXPIRATION_TIME]
            The expiration time of the access token. After this time, the token
            will no longer be usable for authentication. For example, "2024-01-20T12:00:00", with times interpreted in
            UTC timezone.
        .PARAMETER Enable
            Enable the access token.
        .PARAMETER Disable
            Disable the access token. It can no longer be used to authenticate
                        until it is enabled.
        .EXAMPLE
            Modify-QQAccessToken -Id [ACCESS_TOKEN_ID] -Enable [-Json]
            Modify-QQAccessToken -Id [ACCESS_TOKEN_ID] -Disable [-Json]
            Modify-QQAccessToken -Id [ACCESS_TOKEN_ID] -ExpirationTime 1/20/2024" [-Json]
        #>

	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Id,
		[Parameter(Mandatory = $False)] [string]$ExpirationTime,
		[Parameter(Mandatory = $False,ParameterSetName = 'Disable')] [switch]$Disable,
		[Parameter(Mandatory = $False,ParameterSetName = 'Enable')] [switch]$Enable,
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

		# API Request Body
		$body = @{}

		if ($ExpirationTime) {
			try
			{
				$parsedTime = ([datetime]::ParseExact($ExpirationTime,"yyyy-MM-ddTHH:mm:ss",[System.Globalization.CultureInfo]::InvariantCulture))
				$longExpirationTime = "$expirationTime+00:00"
			}
			catch {
				return "Wrong time format.For example, '2024-01-20T12:00:00', with times interpreted in UTC timezone."
				break
			}

			$body.Add("expiration_time",$longExpirationTime)
		}

		if ($Enable) {
			$body.Add("enabled",$True)
		}
		elseif ($Disable) {
			$body.Add("enabled",$False)
		}

		Write-Debug ($body | ConvertTo-Json -Depth 10)

		# API url definition
		$url = "/v1/auth/access-tokens/$Id"

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

function Delete-QQAccessToken {
<#
    .SYNOPSIS
        Delete the specified access token
    .DESCRIPTION
        Get metadata about the specified access token.
    .PARAMETER Id [Token ID]
        Delete the specified access token.
    .EXAMPLE
        Get-QQAccessToken -Id [Token ID] [-Json]
    .LINK
        https://docs.qumulo.com/administrator-guide/external-services/using-access-tokens.html
    #>

	# CmdletBinding parameters.
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [string]$Id,
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
		$url = "/v1/auth/access-tokens/$Id"

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Response
			if ($json) {
				return ("$Id was deleted successfully.")
			}
			else {
				return ("$Id was deleted successfully.")
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
