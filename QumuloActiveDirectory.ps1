<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloActiveDirectory.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo Active Directory configurations and operations
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
function Get-QQADSettings {
<#
        .SYNOPSIS
            Get advanced Active Directory settings
        .DESCRIPTION
            Get advanced Active Directory settings
        .EXAMPLE
            Get-QQADSettings [-Json]
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
		$url = "/v1/ad/settings"

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

function Get-QQADStatus {
<#
        .SYNOPSIS
            Get Active Directory configuration and status.
        .DESCRIPTION
            Get Active Directory configuration and status.
        .EXAMPLE
            Get-QQADStatus [-Json]
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

		$TokenHeader = @{
			Authorization = "Bearer $bearerToken"
		}

		# API url definition
		$url = "/v1/ad/status"

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

function Get-QQADStatus {
<#
        .SYNOPSIS
            Get details on a join or leave operation
        .DESCRIPTION
            Get details on a join or leave operation
        .EXAMPLE
            Get-QQADPoll [-Json]
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

		$TokenHeader = @{
			Authorization = "Bearer $bearerToken"
		}

		# API url definition
		$url = "/v1/ad/monitor"

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
function Join-QQADDomain {
<#
        .SYNOPSIS
            Join an Active Directory Domain
        .DESCRIPTION
            Joins the cluster to an Active Directory domain.
        .PARAMETER Domain [DOMAIN]
            Fully-qualified name of Active Directory Domain
        .PARAMETER Username [USERNAME]
            Domain user to perform the operation, e.g., Administrator
        .PARAMETER Password [PASSWORD]
            Domain password (insecure, visible via ps)
        .PARAMETER DomainNetbios [DOMAIN_NETBIOS]
            NetBIOS name of the domain. By default, the first part of the domain name is used.
        .PARAMETER Ou [OU]
            Organizational Unit to join to
        .PARAMETER UseADPosixAttributes
            Use AD POSIX attributes.
        .PARAMETER BaseDn [BASE_DN]     
            When using LDAP POSIX extensions, query using this base DN
        .EXAMPLE
            Join-QQADDomain -Domain [DOMAIN] -Username [USERNAME] -Password [PASSWORD]   [-Json]
        #>

	# CmdletBinding parameters
	[CmdletBinding(DefaultParameterSetName = 'Secret')]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $True)] [string]$Domain,
		[Parameter(Mandatory = $True)] [string]$User,
		[Parameter(Mandatory = $True,ParameterSetName = 'Secret')] [Security.SecureString]${ADPassword},
		[Parameter(Mandatory = $True,ParameterSetName = 'Plain')] [string]$Password,
		[Parameter(Mandatory = $False)] [string]$DomainNetbios,
		[Parameter(Mandatory = $False)] [string]$Ou,
		[Parameter(Mandatory = $False)] [bool]$UseADPosixAttributes = $False,
		[Parameter(Mandatory = $False)] [string]$BaseDn
	)
	if ($SkipCertificateCheck -eq 'true') {
		$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
	}

	# Password parameter checks and conversion for the required formats. 
	if ($Password) {
		$SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
	}
	else {
		$SecurePassword = ${ADPassword}
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

		# API Request Body
		$Body = @{
			'user' = $User
			'password' = ConvertFrom-SecureString -SecureString $SecurePassword -AsPlainText
			'domain' = $Domain
			'domain_netbios' = $DomainNetbios
			'ou' = $Ou
			'use_ad_posix_attributes' = $UseADPosixAttributes
			'base_dn' = $BaseDn
		}

		Write-Debug ($body | ConvertTo-Json -Depth 10)

		# API url definition
		$url = "/v1/ad/join"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

			# Response
			# API url definition
			$url = "/v1/ad/monitor"

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
	catch {
		$_.Exception.Response
	}
}

function Leave-QQADDomain {
<#
        .SYNOPSIS
            Removes the cluster from Active Directory.
        .DESCRIPTION
            Leave an Active Directory Domain. If domain username is provided, attempt to remove machine account from Active Directory.
        .PARAMETER Domain [DOMAIN]
            Fully-qualified name of Active Directory Domain
        .PARAMETER Username [USERNAME]
            Domain user to perform the operation, e.g., Administrator
        .PARAMETER Password [PASSWORD]
            Domain password (insecure, visible via ps)
        .EXAMPLE
            Leave-QQADDomain -Domain [DOMAIN] -Username [USERNAME] -Password [PASSWORD] [-Json]
        #>

	# CmdletBinding parameters
	[CmdletBinding(DefaultParameterSetName = 'Secret')]
	param(
		[Parameter(Mandatory = $True)] [string]$Domain,
		[Parameter(Mandatory = $True)] [string]$Username,
		[Parameter(Mandatory = $True,ParameterSetName = 'Secret')] [Security.SecureString]${ADPassword},
		[Parameter(Mandatory = $True,ParameterSetName = 'Plain')] [string]$Password,
		[Parameter(Mandatory = $False)] [switch]$Json
	)
	if ($SkipCertificateCheck -eq 'true') {
		$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
	}

	# Password parameter checks and conversion for the required formats. 
	if ($Password) {
		$SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
	}
	else {
		$SecurePassword = ${ADPassword}
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

		# API request body
		$Body = @{
			'domain' = $Domain
			'user' = $Username
			'password' = ConvertFrom-SecureString -SecureString $SecurePassword -AsPlainText
		}

		Write-Debug ($body | ConvertTo-Json -Depth 10)

		# API url definition
		$url = "/v1/ad/leave"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

			# Response
			# API url definition
			$url = "/v1/ad/monitor"

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
	catch {
		$_.Exception.Response
	}
}

function Cancel-QQADOperation {
<#
    .SYNOPSIS
        Cancel current join or leave operation.
    .DESCRIPTION
        Cancel current AD join/leave operation and clear errors
    .EXAMPLE
        Cancel-QQADOperation [-Json]
    #>

	# CmdletBinding parameters
	[CmdletBinding(DefaultParameterSetName = 'Secret')]
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

		$TokenHeader = @{
			Authorization = "Bearer $bearerToken"
		}

		# API url definition
		$url = "/v1/ad/cancel"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

			# Response
			# API url definition
			$url = "/v1/ad/monitor"

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
	catch {
		$_.Exception.Response
	}
}

function Set-QQADSettings {
<#
    .SYNOPSIS
        Modify advanced Active Directory settings
    .DESCRIPTION
        Sets advanced Active Directory settings.
    .PARAMETER  Signing [NO_SIGNING|REQUIRE_SIGNING|WANT_SIGNING]
        Configure DCERPC signing to be off, prefer signing, or require signing. The default is to prefer signing.
    .PARAMETER Sealing  [NO_SEALING|REQUIRE_SEALING|WANT_SEALING]
        Configure DCERPC sealing to be off, prefer sealing, or require sealing. The default is to prefer sealing.
    .PARAMETER Crypto  [NO_AES|REQUIRE_AES|WANT_AES]
        Configure DCERPC to not use encryption, prefer AES encryption, or require AES encryption. The default is to prefer AES encryption.
    .EXAMPLE
            Modify-QQADSettings -Signing [NO_SIGNING|REQUIRE_SIGNING|WANT_SIGNING] -Sealing  [NO_SEALING|REQUIRE_SEALING|WANT_SEALING] -Crypto  [NO_AES|REQUIRE_AES|WANT_AES]  [-Json]
    #>

	# CmdletBinding parameters
	[CmdletBinding(DefaultParameterSetName = 'Secret')]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $False)][ValidateSet("NO_SIGNING","REQUIRE_SIGNING","WANT_SIGNING")] [string]$Signing,
		[Parameter(Mandatory = $False)][ValidateSet("NO_SEALING|","REQUIRE_SEALING|","WANT_SEALING|")] [string]$Sealing,
		[Parameter(Mandatory = $False)][ValidateSet("NO_AES","REQUIRE_AES","WANT_AES")] [string]$Crypto
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

		# API request body
		# API url definition
		$url = "/v1/ad/settings"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Response
			$Body = $response

			if ($Signing) { $Body.signing = $Signing }
			if ($Sealing) { $Body.sealing = $Sealing }
			if ($Crypto) { $Body.crypto = $Crypto }

			Write-Debug ($Body | ConvertTo-Json -Depth 10)
		}
		catch {
			$_.Exception.Response
		}

		# API url definition
		$url = "/v1/ad/settings"

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

function Reconfigure-QQADDomain {
<#
    .SYNOPSIS
        Reconfigure Active Directory POSIX Attributes
    .DESCRIPTION
        Enables/disables POSIX attributes, sets Base DN.
    .PARAMETER UseADPosixAttributes [$true|$false]
        Use AD POSIX attributes.
    .PARAMETER BaseDn [BASE_DN]     
        When using LDAP POSIX extensions, query using this base DN
    .EXAMPLE
        Reconfigure-QQADDomain -UserADPosixAttributes [$true|$false] -BaseDN [BASE_DN]  [-Json]
    #>

	# CmdletBinding parameters
	[CmdletBinding(DefaultParameterSetName = 'Secret')]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json,
		[Parameter(Mandatory = $False)] [bool]$UseADPosixAttributes,
		[Parameter(Mandatory = $False)] [string]$BaseDn
	)
	if ($SkipCertificateCheck -eq 'true') {
		$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
	}

	# Password parameter checks and conversion for the required formats. 
	if ($Password) {
		$SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
	}
	else {
		$SecurePassword = ${ADPassword}
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

		# API request body
		# API url definition
		$url = "/v1/ad/status"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			$Body = @{}
			if (!$BaseDn) {
				$Body += @{ 'base_dn' = $response.base_dn }
			}
			else {
				$Body += @{ 'base_dn' = $BaseDn }
			}

			if (!$UseADPosixAttributes) {
				$Body += @{ 'use_ad_posix_attributes' = $response.use_ad_posix_attributes }
			}
			else {
				$Body += @{ 'use_ad_posix_attributes' = $UseADPosixAttributes }
			}

			Write-Debug ($Body | ConvertTo-Json -Depth 10)
		}
		catch {
			$_.Exception.Response
		}

		# API url definition
		$url = "/v1/ad/reconfigure"

		# API call run
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

			# Response
			# API url definition
			$url = "/v1/ad/monitor"

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
	catch {
		$_.Exception.Response
	}
}


function Get-QQADDNToAccount {
<#
    .SYNOPSIS
        Get all account info for a distinguished name
    .DESCRIPTION
        Get all account info for a distinguished name
    .PARAMETER DistinguishedName [DISTINGUISHED_NAME]
        Get the account with this DN (e.g. CN=user,DC=example,DC=com)
    .EXAMPLE
        Get-QQADDNToAccount -DistinguishedName [DISTINGUISHED_NAME] [-Json]
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$DistinguishedName,
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
		$dn = ([uri]::EscapeDataString($DistinguishedName))
		$url = "/v1/ad/distinguished-names/$dn/object"

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


function Get-QQADUserSIDs {
<#
    .SYNOPSIS
        Get all account info for a distinguished name
    .DESCRIPTION
        Get all account info for a distinguished name
    .PARAMETER Username [USERNAME]
        Get the SIDs that correspond to this username
    .EXAMPLE
        Get-QQADUserSIDs -Username [USERNAME] [-Json]
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Username,
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
		$url = "/v1/ad/usernames/$Username/sids/"

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

function Get-QQADUIDtoSIDs {
<#
    .SYNOPSIS
        Get SIDs from UID
    .DESCRIPTION
        Get SIDs from UID
    .PARAMETER Uid [UID]
        Get the SIDs that correspond to this UID
    .EXAMPLE
        Get-QQADUIDtoSIDs -UID [UID] [-Json]
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Uid,
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
		$url = "/v1/ad/uids/$Uid/sids/"

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


function Get-QQADSIDtoUID {
<#
    .SYNOPSIS
        Get UID from SID
    .DESCRIPTION
        Get UID from SID
    .PARAMETER Sid [SID]
        Get the UID that corresponds to this SID
    .EXAMPLE
        Get-QQADSIDtoUID -Sid [SID] [-Json]
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Sid,
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
		$url = "/v1/ad/sids/$Sid/uid"

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

function Get-QQADSIDtoUsername {
<#
    .SYNOPSIS
        Get AD username from SID
    .DESCRIPTION
        Get AD username from SID
    .PARAMETER Sid [SID]
        Get the username that corresponds to this SID
    .EXAMPLE
        Get-QQADSIDtoUsername -Sid [SID] [-Json]
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Sid,
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
		$url = "/v1/ad/sids/$Sid/username"

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

function Get-QQADSIDtoGID {
<#
    .SYNOPSIS
        Get GID from SID
    .DESCRIPTION
        Get GID from SID
    .PARAMETER Sid [SID]
        Get the GID that corresponds to this SID
    .EXAMPLE
        Get-QQADSIDtoGID -Sid [SID] [-Json]
    #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Sid,
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
		$url = "/v1/ad/sids/$Sid/gid"

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

function Get-QQADGIDtoSIDs {
<#
        .SYNOPSIS
            Get SIDs from GID
        .DESCRIPTION
            Get SIDs from GID
        .PARAMETER Uid [UID]
            Get the SIDs that correspond to this GID
        .EXAMPLE
            Get-QQADUIDtoSIDs -GID [GID] [-Json]
        #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Gid,
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
		$url = "/v1/ad/gids/$Gid/sids/"

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


function Get-QQADSIDtoExpandedGroupSIDs {
<#
        .SYNOPSIS
            Get SID to Expanded Group SIDs
        .DESCRIPTION
            Get SID to Expanded Group SIDs
        .PARAMETER Sid [SID]
            Get the GID that corresponds to this SID
        .EXAMPLE
            Get-QQADSIDtoExpandedGroupSID -Sid [SID] [-Json]
        #>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Sid,
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
		$url = "/v1/ad/sids/$Sid/expanded-groups/"

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
