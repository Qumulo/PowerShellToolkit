<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloMultitenancy.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo multitenancy configurations and operations
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
function List-QQTenants {
<#
    .SYNOPSIS
        List all tenants
    .DESCRIPTION
        Get configurations of all tenants.
    .EXAMPLE
        List-QQTenants [-Json]
    .LINK
        
    #>

    # CmdletBinding parameters. 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)]
        [switch]$json
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
        $url = "/v1/multitenancy/tenants/"

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

function Get-QQTenant {
<#
    .SYNOPSIS
        Get a tenant
    .DESCRIPTION
        Get configuration of a tenant.
    .PARAMETER Id [TENANT_ID]
        The unique ID of the tenant to retrieve.
    .EXAMPLE
        Get-QQTenant -Id [TENANT_ID] [-Json]
    .LINK
        
    #>

    # CmdletBinding parameters. 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$json,
        [Parameter(Mandatory = $True)][string]$Id
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
        $url = "/v1/multitenancy/tenants/$Id"

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

function Set-QQMultitenancy {
<#
    .SYNOPSIS
        Enable multitenancy and create the first tenant or disable multitenancy and remove all tenants
    .DESCRIPTION
        Enabling Multitenancy allows access to different management and data protocols to be isolated to specific
        tenants by network, including tagged VLANs or the untagged network. Individual services can be
        enabled or disabled for each tenant to allow or disallow access to that protocol on the networks
        associated with the tenant.

        By default, when no tenants are configured, all multitenancy-aware services are available on all
        networks to which the cluster is connected, excepting those services which must be explicitly
        enabled cluster-wide through their own separate server settings.

        When multitenancy is enabled, the first tenant is created and all existing networks and
        tenant-assignable resources are automatically assigned to this tenant. All multitenancy-aware
        services are enabled to start but may be disabled through multitenancy_modify_tenant. Additional
        tenants may be created through multitenancy_create_tenant. New networks and tenant-assignable
        resources must be explicitly assigned to a tenant.

        WARNING: It is possible for access to services to be disabled on all networks, including
        management services such as the REST API, Web UI, and SSH, effectively disabling remote
        administrative access to the cluster. Management services are always available locally through
        a remote or physical server console.

        Disabling multitenancy allows delete the last tenant and disable multitenancy

        Deletes the last and only tenant. See `multitenancy_delete_tenant` to delete tenants.

        WARNING: Disabling multitenancy will delete the last tenant, immediately unassigning any
        networks and making all services accessible on all configured networks.
    .PARAMETER Name [TENANT_NAME]
        Unique name of the tenant chosen by the user.
    .PARAMETER Enable
        Enable multitenancy
    .PARAMETER Disable 
        Disable multitenancy
    .EXAMPLE
        Set-QQMultitenancy -Enable -Name [NAME]
        Set-QQMultitenancy -Disable 
    #>

    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json,
        [Parameter(Mandatory = $False, ParameterSetName='Enable')][string]$Name,
        [Parameter(Mandatory = $False, ParameterSetName='Enable')][switch]$Enable,
		[Parameter(Mandatory = $False, ParameterSetName='Disable')][switch]$Disable
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

        if($enable){
            # API body
            $body = @{ 'name' = $Name }

            # API url definition
            $url = "/v1/multitenancy/enable"
        }
        elseif($disable){
            # API url definition
            $url = "/v1/multitenancy/disable"
        }
        

        # API call run
        try {
            $response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
            # Response
            if($Disable){
                # API url definition
                $url = "/v1/multitenancy/tenants/"

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
            else{
                if ($json) {
                    return @($response) | ConvertTo-Json -Depth 10
                }
                else {
                    return $response
                }
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

function Create-QQTenant {
<#
    .SYNOPSIS
        Create a tenant
    .DESCRIPTION
        Multitenancy allows access to different management and data protocols to be isolated to specific
        tenants by network, including tagged VLANs or the untagged network. Individual services can be
        enabled or disabled for each tenant to allow or disallow access to that protocol on the networks
        associated with the tenant.

        By default, when no tenants are configured, all multitenancy-aware services are available on all
        networks to which the cluster is connected, excepting those services which must be explicitly
        enabled cluster-wide through their own separate server settings.

        When multitenancy is enabled, the first tenant is created and all existing networks and
        tenant-assignable resources are automatically assigned to this tenant. All multitenancy-aware
        services are enabled to start but may be disabled through multitenancy_modify_tenant. Additional
        tenants may be created through multitenancy_create_tenant. New networks and tenant-assignable
        resources must be explicitly assigned to a tenant.

        WARNING: It is possible for access to services to be disabled on all networks, including
        management services such as the REST API, Web UI, and SSH, effectively disabling remote
        administrative access to the cluster. Management services are always available locally through
        a remote or physical server console.
    .PARAMETER Name [TENANT_NAME]
        Unique name of the tenant chosen by the user.
  --network-id [NETWORK_ID [NETWORK_ID ...]]
                        List of zero or more network IDs associated with this tenant, as
                        returned by the `network_list_networks` command. Each network ID may
                        be assigned to at most one tenant.
  --enable-web-ui       Web UI is accessible from this tenant.
  --disable-web-ui      Web UI is not accessible from this tenant. This is the default.
  --enable-rest-api     REST API is accessible from this tenant.
  --disable-rest-api    REST API is not accessible from this tenant. This is the default.
  --enable-ssh          SSH is accessible from this tenant.
  --disable-ssh         SSH is not accessible from this tenant. This is the default.
  --enable-replication  Replication is accessible from this tenant.
  --disable-replication
                        Replication is not accessible from this tenant. This is the default.
  --enable-nfs          NFS is accessible from this tenant.
  --disable-nfs         NFS is not accessible from this tenant. This is the default.
  --enable-smb          SMB is accessible from this tenant.
  --disable-smb         SMB is not accessible from this tenant. This is the default.
    .EXAMPLE
        Set-QQMultitenancy -Enable -Name [NAME]
        Set-QQMultitenancy -Disable 
    #>

    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json,
        [Parameter(Mandatory = $True)][string]$Name,
        [Parameter(Mandatory = $False)][string]$NetworkId,
        [Parameter(Mandatory = $False)][string]$ADDomain,
        [Parameter(Mandatory = $False)][switch]$EnableWebUI,
        [Parameter(Mandatory = $False)][switch]$DisableWebUI,
        [Parameter(Mandatory = $False)][switch]$EnableRestAPI,
        [Parameter(Mandatory = $False)][switch]$DisableRestAPI,
        [Parameter(Mandatory = $False)][switch]$EnableSsh,
        [Parameter(Mandatory = $False)][switch]$DisableSsh,
        [Parameter(Mandatory = $False)][switch]$EnableReplication,
        [Parameter(Mandatory = $False)][switch]$DisableReplication,
        [Parameter(Mandatory = $False)][switch]$EnableNFS,
        [Parameter(Mandatory = $False)][switch]$DisableNFS,
        [Parameter(Mandatory = $False)][switch]$EnableSMB,
        [Parameter(Mandatory = $False)][switch]$DisableSMB
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

        $body = @{ 'name' = $Name }

        if ($NetworkId){
            $body.Add('networks', $NetworkId.Split(','))
        }

        if ($EnableWebUI){
            $body.Add('web_ui_enabled',$true)
        }
        elseif ($DisableWebUI){
            $body.Add('web_ui_enabled',$false)
        }

        if ($EnableRestAPI){
            $body.Add('rest_api_enabled',$true)
        }
        elseif ($DisableRest){
            $body.Add('rest_api_enabled',$false)
        }

        if ($EnableSsh){
            $body.Add('ssh_enabled',$true)
        }
        elseif ($DisableSsh){
            $body.Add('ssh_enabled',$false)
        }

        if ($EnableReplication){
            $body.Add('replication_enabled',$true)
        }
        elseif ($DisableReplication){
            $body.Add('replication_enabled',$false)
        }

        if ($EnableNFS){
            $body.Add('nfs_enabled',$true)
        }
        elseif ($DisableNFS){
            $body.Add('nfs_enabled',$false)
        }

        if ($EnableSMB){
            $body.Add('smb_enabled',$true)
        }
        elseif ($DisableSMB){
            $body.Add('smb_enabled',$false)
        }
        
        # API url definition
        $url = "/v1/multitenancy/tenants/"

        # API call run
        try {
            $response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
            # Response
            if($Disable){
                # API url definition
                $url = "/v1/multitenancy/tenants/"

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
            else{
                if ($json) {
                    return @($response) | ConvertTo-Json -Depth 10
                }
                else {
                    return $response
                }
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
    

function Delete-QQTenant {
<#
    .SYNOPSIS
        Delete a tenant
    .DESCRIPTION
        Delete configuration of a tenant. A tenant may only be deleted if it has no networks assigned.  Use the
        Modify-QQTenant` command to unassign or reassign any associated networks before deleting a tenant. 
        See `Set-QQMultitenancy -Disable to remove the last tenant.
    .PARAMETER Id [TENANT_ID]
        The unique ID of the tenant to retrieve.
    .EXAMPLE
        Delete-QQTenant -Id [TENANT_ID] [-Json]
    .LINK
        
    #>

    # CmdletBinding parameters. 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$json,
        [Parameter(Mandatory = $True)][string]$Id
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
        $url = "/v1/multitenancy/tenants/$Id"

        # API call run	
        try {
            $response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
            # API url definition
            $url = "/v1/multitenancy/tenants/"

            # API call run	
            try {
                $list = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

                # Response
                if ($json) {
                    return @($list) | ConvertTo-Json -Depth 10
                }
                else {
                    return $list
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
    