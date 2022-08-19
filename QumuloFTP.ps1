<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloFTP.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo FTP configurations and operations
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
function Get-QQFTPStatus {
<#
    .SYNOPSIS
        Get FTP server status
    .DESCRIPTION
        Get FTP server status
    .EXAMPLE
    	Get-QQFTPStatus [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115014912268-FTP-in-Qumulo-Core#active-directory-users-for-ftp-0-7
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
		$url = "/v0/ftp/status"

		# API call run	
		try {
			$response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

			# Response
			if ($Json) {
				return @($response.statuses) | ConvertTo-Json -Depth 10
			}
			else {
				return $response.statuses
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

function Get-QQFTPSettings {
	<#
		.SYNOPSIS
			Get FTP server settings
		.DESCRIPTION
			Get FTP server settings
		.EXAMPLE
			Get-QQFTPSettings [-Json]
		.LINK
			https://care.qumulo.com/hc/en-us/articles/115014912268-FTP-in-Qumulo-Core#active-directory-users-for-ftp-0-7
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
			$url = "/v0/ftp/settings"
	
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

function Modify-QQFTPSettings {
<#
    .SYNOPSIS
        Set FTP server settings
    .DESCRIPTION
        Set FTP server settings
	.PARAMETER Limit LIMIT
		Base-2 shorthand names are accepted: GB, TB (e.g. 50GB)
	.PARAMETER Id [File ID]
		Directory ID
	.PARAMETER Path [Directory Path]
		Directory path
    .EXAMPLE
       Modify-QQFTPSettings -Enabled [$true|$false]
	   Modify-QQFTPSettings -CheckRemoteHost [$true|$false]
	   Modify-QQFTPSettings -LogOperations [$true|$false]
	   Modify-QQFTPSettings -ChrootUsers [$true|$false]
	   Modify-QQFTPSettings -AllowUnencryptedConnections [$true|$false]
	   Modify-QQFTPSettings -ExpandWildcards [$true|$false]
	   Modify-QQFTPSettings -AnonymousUserAsLocalUser [ANONYMOUS_USER_AS_LOCAL_USER]
	   Modify-QQFTPSettings -AnonymousUserNone
	   Modify-QQFTPSettings -Greeting [GREETING]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/115009394288-Quotas-in-Qumulo-Core
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)][ValidateSet("True", "False")][string]$Enabled,
		[Parameter(Mandatory = $False)][ValidateSet("True", "False")][string]$CheckRemoteHost,
		[Parameter(Mandatory = $False)][ValidateSet("True", "False")][string]$LogOperations,
		[Parameter(Mandatory = $False)][ValidateSet("True", "False")][string]$ChrootUsers,
		[Parameter(Mandatory = $False)][ValidateSet("True", "False")][string]$AllowUnencryptedConnections,
		[Parameter(Mandatory = $False)][ValidateSet("True", "False")][string]$ExpandWildcards,
		[Parameter(Mandatory = $False)][switch]$AnonymousUserNone,
		[Parameter(Mandatory = $False)][string]$AnonymousUserAsLocalUser,
		[Parameter(Mandatory = $False)][string]$Greeting,
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


			# API url definition
			$url = "/v0/ftp/settings"

			# API body definition
			$body = @{}

			if($Enabled){
				if($Enabled -eq "True"){$body += (@{ enabled = $True})}
				elseif($Enabled -eq "False"){$body += (@{ enabled = $False})}
			}
			if($CheckRemoteHost){
				if($CheckRemoteHost -eq "True"){$body += (@{ check_remote_host = $True})}
				elseif($CheckRemoteHost -eq "False"){$body += (@{ check_remote_host = $False})}
			}
			if($LogOperations){
				if($LogOperations -eq "True"){$body += (@{ log_operations = $True})}
				elseif($LogOperations -eq "False"){$body += (@{ log_operations = $False})}
			}
			if($ChrootUsers){
				if($ChrootUsers -eq "True"){$body += (@{ chroot_users = $True})}
				elseif($ChrootUsers -eq "False"){$body += (@{ chroot_users = $False})}
			}
			if($AllowUnencryptedConnections){
				if($AllowUnencryptedConnections -eq "True"){$body += (@{ allow_unencrypted_connections = $True})}
				elseif($AllowUnencryptedConnections -eq "False"){$body += (@{ allow_unencrypted_connections = $False})}
			}
			if($ExpandWildcards){
				if($ExpandWildcards -eq "True"){$body += (@{ expand_wildcards = $True})}
				elseif($ExpandWildcards -eq "False"){$body += (@{ expand_wildcards = $False})}
			}
			if($AnonymousUserAsLocalUser){$body += (@{ anonymous = $AnonymousUserAsLocalUser})}
			if($AnonymousUserNone){$body += (@{  anonymous = ""})}
			if($Greeting){$body += (@{ greeting = $Greeting})}

			Write-Debug($body | ConvertTo-Json -Depth 10)

			# API call run
			try {
				$response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

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
