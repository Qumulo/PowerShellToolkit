<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloFile.ps1
	Module Name: 	Qumulo 
	Description: 	PowerShell Script (.ps1) for Qumulo file configurations and operations
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
function Get-QQFileAttr {
<#
    .SYNOPSIS
        Retrieve file attributes
    .DESCRIPTION
        Retrieve file attributes
    .PARAMETER Id [Directory or file name]File ID]
        Directory or File ID
    .PARAMETER Path [Directory  or File Path]
        Directory or File path
    .EXAMPLE
        Get-QQFileAttr -Id [Directory or File ID] 
        Get-QQFileAttr -Path [Directory or File Path] 
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
        [Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
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
        }
        elseif($id){
            $url = "/v1/files/$id/info/attributes"
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

function Get-QQFileAcl {
<#
    .SYNOPSIS
        Get file ACL
    .DESCRIPTION
        Retrieve file ACL
    .PARAMETER Id [Directory or File ID]
        Directory or File ID
    .PARAMETER Path [Directory or FilePath]
        Directory or File path
    .PARAMETER Snapshot [Snapshot ID]
        Snapshot ID to read from
    .EXAMPLE
        Get-QQFileAcl -Id [File ID] 
        Get-QQFileAcl -Path [Directory Path] 
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
        [Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
        [Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()] [string]$Snapshot,
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
            $url = "/v1/files/$htmlPath/info/acl"
        }
        elseif($id){
            $url = "/v1/files/$id/info/acl"
        }

        if($snapshot){
            $url +="?snapshot=" + $Snapshot
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


function Create-QQNewDir {
    <#
        .SYNOPSIS
            Create a new directory 
        .DESCRIPTION
            Create a new directory 
        .PARAMETER Path [Directory Path]
            Directory path
        .PARAMETER Name [New Directory Name]
            Directory name
        .EXAMPLE
            Create-QQNewDir -Path [Directory Path] -Name [Directory Name]
        #>
    
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $True)][string]$Path,
            [Parameter(Mandatory = $True)][string]$Name,
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
    

            $htmlPath = ([uri]::EscapeDataString($path))
            # API url definition
            $url = "/v1/files/$htmlPath/entries/"

            # API Request body
            $body = @{
                "name" =  $Name
                "action" = "CREATE_DIRECTORY"
            }


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

function Set-QQFileAttr {
<#
    .SYNOPSIS
        Set file attributes
    .DESCRIPTION
        Set file attributes. Changing owner or mode bits is done POSIX-style; file's ACL is updated to match the requested permissions.
    .PARAMETER Id [Directory or file name]File ID]
        Directory or File ID
    .PARAMETER Path [Directory  or File Path]
        Directory or File path
    .PARAMETER OwnerSID
    Owner SID
    .EXAMPLE
        Set-QQFileAttr -Id [Directory or File ID] 
        Set-QQFileAttr -Path [Directory or File Path] 
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True,ParameterSetName = "Id")][ValidateNotNullOrEmpty()] [string]$Id,
        [Parameter(Mandatory = $True,ParameterSetName = "Path")][ValidateNotNullOrEmpty()] [string]$Path,
    [Parameter(Mandatory = $True)][string]$OwnerSID,
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
        }
        elseif($id){
            $url = "/v1/files/$id/info/attributes"
        }

    # API body
    $body = @{
        "owner_details" = @{ 
            "id_type"= "SMB_SID" 
            "id_value"= $OwnerSID
        }
    } 
    Write-Debug($body| ConvertTo-Json -Depth 10) 

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
        
        
    