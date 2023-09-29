<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloAnalytics.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo analytics 
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
function Get-QQTimeSeries {
<#
	.SYNOPSIS
		Get Time Series Statistics
	.DESCRIPTION
		Get Time Series Statistics
	.PARAMETER BeginTime [EPOCH_TIME]
		Begin time for time series intervals, in epoch seconds
	.EXAMPLE
		Get-QQTimeSeries -BeginTime [EPOCH_TIME] [-Json]
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$BeginTime,
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
		$url = "/v1/analytics/time-series/?begin-time=$BeginTime"

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

function Get-QQCurrentActivity {
<#
	.SYNOPSIS
		Get the current sampled IOP and throughput rates
	.DESCRIPTION
		Get the current sampled IOP and throughput rates
	.PARAMETER Type [file-iops-read,file-iops-write,metadata-iops-read,metadata-iops-write,file-throughput-read,file-throughput-write]
		The specific type of throughput to get
	.EXAMPLE
		Get-QQCurrentActivity [-Json]
		Get-QQCurrentActivity -Type [file-iops-read,file-iops-write,metadata-iops-read,metadata-iops-write,file-throughput-read,file-throughput-write] [-Json]
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)][ValidateSet('file-iops-read','file-iops-write','metadata-iops-read','metadata-iops-write','file-throughput-read','file-throughput-write')] [string]$Type,
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
		if ($Type) {
			$url = "/v1/analytics/activity/current?type=$Type"
		}
		else {
			$url = "/v1/analytics/activity/current"
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

function Get-QQCapacityHistory {
<#
	.SYNOPSIS
		Get capacity history data.
	.DESCRIPTION
		Get Capacity Usage History for a Time Window
	.PARAMETER BeginTime [EPOCH_TIME]
		Lower bound on history returned, in epoch seconds
	.PARAMETER EndTime [EPOCH_TIME]
		Upper bound on history returned, in epoch seconds
	.PARAMETER Interval [hourly,daily,weekly]
		The interval at which to sample
	.EXAMPLE
		Get-QQCapacityHistory -BeginTime [EPOCH_TIME] -EndTime [EPOCH_TIME] -Interval [hourly,daily,weekly]
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)][ValidateSet('hourly','daily','weekly')] [string]$Interval,
		[Parameter(Mandatory = $True)] [string]$BeginTime,
		[Parameter(Mandatory = $True)] [string]$EndTime,
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
		$url = "/v1/analytics/capacity-history/?begin-time=$BeginTime&end-time=$EndTime&interval=$Interval"


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

function Get-QQFilesCapacityHistory {
<#
	.SYNOPSIS
		Get historical largest file data.
	.DESCRIPTION
		Get historical largest file data.
	.PARAMETER Timestamp [EPOCH_TIME]
		Time period to retrieve, in epoch seconds.
	.EXAMPLE
		Get-QQFilesCapacityHistory -Timestamp [EPOCH_TIME] [-Json]
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] [string]$Timestamp,
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
		$url = "/v1/analytics/capacity-history/$Timestamp/"


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

