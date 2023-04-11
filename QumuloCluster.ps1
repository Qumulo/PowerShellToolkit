<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloCluster.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo cluster level configurations and operations
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
function Get-QQClusterSettings {
<#
	.SYNOPSIS
		Get the cluster config
	.DESCRIPTION
		Returns cluster settings.
	.EXAMPLE
		Get-QQClusterSettings [-Json]
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
		$url = "/v1/cluster/settings"

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

function List-QQNodes {
<#
    .SYNOPSIS
        List nodes
    .DESCRIPTION
        List nodes or a node details
	.PARAMETER Node [ID]
		The unique ID of the node
    .EXAMPLE
        List-QQNodes [-Json]
		List-QQNodes -Node [ID] [-Json]
    #>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [string]$Node,
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
		if ($Node) {
			$url = "/v1/cluster/nodes/$Node"
		}
		else {
			$url = "/v1/cluster/nodes/"
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

function List-QQUnconfiguredNodes {
	<#
		.SYNOPSIS
			List unconfigured nodes
		.DESCRIPTION
			List unconfigured nodes or a node details
		.EXAMPLE
			List-QQUnconfiguredNodes [-Json]
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
			$url = "/v1/unconfigured/nodes/"

	
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

function Get-QQEncryptionStatus {
<#
	.SYNOPSIS
		View the status of encryption at rest
	.DESCRIPTION
		View the status of encryption at rest.
	.EXAMPLE
		Get-QQEncryptionStatus [-Json]
	.LINK
		https://care.qumulo.com/hc/en-us/articles/360050324194-Qumulo-Core-s-Encryption-at-Rest
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
		$url = "/v1/encryption/status"


		try {
			# API call run	
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

function Get-QQNodeState {
	<#
		.SYNOPSIS
			Get the operational state of the node
		.DESCRIPTION
			Retrieves node state of the node that the call was made to.
		.EXAMPLE
			Get-QQNodeState [-Json]
	#>

	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [switch]$Json
	)
	if ($SkipCertificateCheck -eq 'true') {
		$PSDefaultParameterValues = @("Invoke-RestMethod:SkipCertificateCheck",$true)
		if ($DEBUG) { Write-Host "Skipping the Certificate Check $SkipCertificateCheck" }
		$skipcert = $True
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
		$url = "/v1/node/state"


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

function List-QQClusterSlots {
<#
		.SYNOPSIS
			List slots
		.DESCRIPTION
			List slots or retrieve info about the disk slot, such as its capacity, type, model, etc.
		.PARAMETER Slot ID
			The unique ID of the disk slot
		.EXAMPLE
			List-QQClusterSlots [-Json]
			List-QQClusterSlots -Slot [ID] [-Json]
		#>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [string]$SlotId,
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
		if ($SlotId) {
			$url = "/v1/cluster/slots/$SlotId"
		}
		else {
			$url = "/v1/cluster/slots/"
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

function Get-QQChassisStatus {
<#
		.SYNOPSIS
			Get the status of node chassis
		.DESCRIPTION
			List the status of the chassis for a node or all nodes in the cluster. In particular, it gives the node_id and status of the identifier light.
		.PARAMETER Node ID
			The unique ID of the node
		.EXAMPLE
			Get-QQChassisStatus [-Json]
			Get-QQChassisStatus -Node [ID] [-Json]
		#>
	# CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)] [string]$Node,
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
		if ($Node) {
			$url = "/v1/cluster/nodes/$Node/chassis"
		}
		else {
			$url = "/v1/cluster/nodes/chassis/"
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


function Get-QQProtectionStatus {
<#
    .SYNOPSIS
        Get detailed status information for the data protection of the cluster.
    .DESCRIPTION
        Get detailed status information for the data protection of the cluster.
    .EXAMPLE
        Get-QQProtectionStatus [-Json]
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
		$url = "/v1/cluster/protection/status"

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

function Get-QQRestriperStatus {
<#
	.SYNOPSIS
		Get current status of restriper, including data protection status and current restripe phase (if running).
	.DESCRIPTION
		Get current status of restriper, including data protection status and current restripe phase (if running).
	.EXAMPLE
		Get-QQRestriperStatus [-Json]
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
		$url = "/v1/cluster/restriper/status"

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

function Get-QQVersion {
<#
	.SYNOPSIS
		Retrieve the version of the appliance.
	.DESCRIPTION
		Retrieve the version of the appliance.
	.EXAMPLE
		Get-QQVersion [-Json]
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
		$url = "/v1/version"

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

function Get-QQSSLCaCertificate {
<#
	.SYNOPSIS
		Get SSL CA certificate.
	.DESCRIPTION
		Get SSL CA certificate. This certificate is used to authenticate connections to external LDAP servers.
	.EXAMPLE
		Get-QQSSLCaCertificate [-Json]
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
		$url = "/v2/cluster/settings/ssl/ca-certificate"

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