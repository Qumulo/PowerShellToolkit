<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloNetwork.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo Network configurations and operations
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
function List-QQNetworks {
<#
    .SYNOPSIS
        List network configurations
    .DESCRIPTION
        Get configurations of all networks configured on an interface. This will always include at least one network, and exactly one if it is assigned by DHCP. Network 1 is created by default, but it may be removed if other networks are created via static assignment.
    .EXAMPLE
        List-QQNetworks [-Json]
    .LINK
        https://care.qumulo.com/hc/en-us/articles/115007237948-Connect-to-Multiple-Networks-in-Qumulo-Core
    #>

    # CmdletBinding parameters
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False)][switch]$Json,
        [Parameter(Mandatory = $False)][string]$InterfaceID=1
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
		$url = "/v2/network/interfaces/$InterfaceID/networks/"

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

function Get-QQNetwork {
<#
    .SYNOPSIS
        Get configuration for the specified network
    .DESCRIPTION
        Get configuration of a network on an interface.
    .PARAMETER NetworkID ID
        The unique ID of the network
     .PARAMETER InterfaceID ID
        The unique ID of the interface. Only applicable for All-NVMe nodes
    .EXAMPLE
        Get-QQNetwork -NetworkID [ID] [-Json]
        Get-QQNetwork -NetworkID [ID] -InterfaceID [ID] [-Json] (Only applicable for All-NVMe nodes)
    .LINK
        https://care.qumulo.com/hc/en-us/articles/115007237948-Connect-to-Multiple-Networks-in-Qumulo-Core
    #>

    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json,
        [Parameter(Mandatory = $False)][string]$InterfaceID="1",
        [Parameter(Mandatory = $True)][string]$NetworkID
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
        $url = "/v2/network/interfaces/$interfaceID/networks/$networkID"

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

function Add-QQNetwork {
<#
    .SYNOPSIS
        Add network configuration
    .DESCRIPTION
        Add a network configuration to the interface. If the network being added is an untagged STATIC network, the MTU will be computed based on the interface configuration.
    .PARAMETER Name NAME          
        Network name
    .PARAMETER InterfaceID ID
        The unique ID of the interface. Only applicable for All-NVMe nodes
    .PARAMETER Netmask (if STATIC) 
        IPv4 or IPv6 Netmask  - 255.255.255.0 
    .PARAMETER IpRanges (if STATIC) 
        List of persistent IP ranges. Can be single addresses or ranges, comma separated. eg. 10.1.1.20-21 or 10.1.1.20,10.1.1.21
    .PARAMETER FloatingIpRanges  (if STATIC) 
        List of floating IP ranges. Can be single addresses or ranges, comma separated. eg. 10.1.1.20-21 or 10.1.1.20,10.1.1.21
    .PARAMETER DnsServers         
        List of DNS Server IP addresses. Can be a single address or multiple comma separated addresses. eg. 10.1.1.10 or 10.1.1.10,10.1.1.15
    .PARAMETER DnsSearchDomains   
        List of DNS Search Domains
    .PARAMETER Mtu (if STATIC) 
        The Maximum Transfer Unit (MTU) in bytes of a tagged STATIC network. The MTU of an untagged STATIC network needs to be specified through interface MTU.
    .PARAMETER VlanID (if STATIC) 
        User assigned VLAN tag for network configuration. 1-4094 are valid VLAN IDs and 0 is used for untagged networks.
    .EXAMPLE
        Add-QQNetwork -Name [NAME] -Netmask [SUBNET_MASK] -IpRange [LIST_OF_IPS] -FloatingIpRanges [LIST_OF_IPS] -DnsServers [LIST_OF_DNS_SERVER] -DnsSearchDomains [DOMAIN_NAME] -Mtu [1500|9000] -VlanID [0-4094] 
    .LINK
        https://care.qumulo.com/hc/en-us/articles/115007237948-Connect-to-Multiple-Networks-in-Qumulo-Core
    #>

    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json,
        [Parameter(Mandatory = $False)][string]$InferfaceID="1",
        [Parameter(Mandatory = $True)][string]$Name,
        [Parameter(Mandatory = $True)][string]$Netmask,
        [Parameter(Mandatory = $True)][array]$IpRanges,
        [Parameter(Mandatory = $False)][array]$FloatingIpRanges,
        [Parameter(Mandatory = $False)][array]$DnsServers,
        [Parameter(Mandatory = $False)][array]$DnsSearchDomains,
        [Parameter(Mandatory = $True)][int16]$MTU,
        [Parameter(Mandatory = $True)][int16]$VlanID
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

        # API Request Body
        if(!$DnsSearchDomains){$DnsSearchDomains = @()}
        if(!$FloatingIpRanges){$FloatingIpRanges = @()}
        if(!$DnsServers){$DnsServers = @()}
        $body = @{
            "floating_ip_ranges" = $FloatingIpRanges
            "dns_search_domains" = $DnsSearchDomains
            "mtu" = $Mtu
            "netmask" = $Netmask 
            "vlan_id" = $VlanID 
            "name" = $Name
            "assigned_by" = "STATIC" 
            "ip_ranges" = $IpRanges 
            "dns_servers" = $DnsServers
        }

        Write-Debug($body| ConvertTo-Json -Depth 10)

        # API call run
        $url = "/v2/network/interfaces/$InterfaceID/networks/"
        
        # API call run	
        try {
            $response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

            # Response (Existing network configurations)
            $url = "/v2/network/interfaces/$InterfaceID/networks/"
            $DetailedResponse = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

            if ($json) {
                return @($DetailedResponse) | ConvertTo-Json -Depth 10
            }
            else {
                return $DetailedResponse
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

function Delete-QQNetwork {
<#
    .SYNOPSIS
        Delete network configuration
    .DESCRIPTION
        Delete configuration of a network on an interface.
     .PARAMETER NetworkID ID
        The unique ID of the network
    .EXAMPLE
        Get-QQNetwork -NetworkID [ID] [-Json]
    .LINK
        https://care.qumulo.com/hc/en-us/articles/115007237948-Connect-to-Multiple-Networks-in-Qumulo-Core
    #>
    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json,
        [Parameter(Mandatory = $True)][string]$NetworkID
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
        $url = "/v2/network/interfaces/1/networks/$NetworkID"
        
        # API call run
        try {
            $response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

            # Response (Existing network configurations)
            $url = "/v2/network/interfaces/1/networks/"
            $DetailedResponse = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

            if ($json) {
                return @($DetailedResponse) | ConvertTo-Json -Depth 10
            }
            else {
                return $DetailedResponse
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

function Modify-QQNetwork {
<#
        .SYNOPSIS
        Modify a network configuration
    .DESCRIPTION
        Update a subset of configuration of a network on an interface. MTU change will not be allowed if the network being updated is an untagged STATIC network. Please modify the interface config instead.
    .PARAMETER NetworkID ID
        Network ID
    .PARAMETER Name NAME          
        Network name
    .PARAMETER InterfaceID ID
        The unique ID of the interface. Only applicable for All-NVMe nodes
    .PARAMETER Netmask (if STATIC) 
        IPv4 or IPv6 Netmask  - 255.255.255.0 
    .PARAMETER IpRanges (if STATIC) 
        List of persistent IP ranges. Can be single addresses or ranges, comma separated. eg. 10.1.1.20-21 or 10.1.1.20,10.1.1.21
    .PARAMETER FloatingIpRanges  (if STATIC) 
        List of floating IP ranges. Can be single addresses or ranges, comma separated. eg. 10.1.1.20-21 or 10.1.1.20,10.1.1.21
    .PARAMETER DnsServers         
        List of DNS Server IP addresses. Can be a single address or multiple comma separated addresses. eg. 10.1.1.10 or 10.1.1.10,10.1.1.15
    .PARAMETER DnsSearchDomains   
        List of DNS Search Domains
    .PARAMETER Mtu (if STATIC) 
        The Maximum Transfer Unit (MTU) in bytes of a tagged STATIC network. The MTU of an untagged STATIC network needs to be specified through interface MTU.
    .PARAMETER VlanID (if STATIC) 
        User assigned VLAN tag for network configuration. 1-4094 are valid VLAN IDs and 0 is used for untagged networks.
    .EXAMPLE
        Modify-QQNetwork -NetworkID [ID] -Name [NAME] -Netmask [SUBNET_MASK] -IpRange [LIST_OF_IPS] -FloatingIpRanges [LIST_OF_IPS] -DnsServers [LIST_OF_DNS_SERVER] -DnsSearchDomains [DOMAIN_NAME] -Mtu [1500|9000] -VlanID [0-4094] 
    .LINK
        https://care.qumulo.com/hc/en-us/articles/115007237948-Connect-to-Multiple-Networks-in-Qumulo-Core
    #>

    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json,
        [Parameter(Mandatory = $True)][string]$NetworkID,
        [Parameter(Mandatory = $False)][string]$Name,
        [Parameter(Mandatory = $False)][string]$Netmask,
        [Parameter(Mandatory = $False)][array]$IpRanges,
        [Parameter(Mandatory = $False)][array]$FloatingIpRanges,
        [Parameter(Mandatory = $False)][array]$DnsServers,
        [Parameter(Mandatory = $False)][array]$DnsSearchDomains,
        [Parameter(Mandatory = $False)][int16]$MTU,
        [Parameter(Mandatory = $False)][int16]$VlanID
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

        # API Request Body
        $body = @{
            "id" = [int16]$networkID
        }

        if($Name){ $body += @{"name" = $Name}}
        if($Netmask){ $body += @{"netmask" = $Netmask}}
        if($IpRanges){ $body += @{"ip_ranges" = $IpRanges}}
        if($FloatingIpRanges){ $body += @{"floating_ip_ranges" = $FloatingIpRanges}}
        if($DnsServers){ $body += @{"dns_servers" = $DnsServers}}
        if($DnsSearchDomains){ $body += @{"dns_search_domains" = $DnsSearchDomains}}
        if($MTU){ $body += @{"mtu" = $MTU}}
        if($VlanID){ $body += @{"vlan_id" = $VlanID}}

        Write-Debug($body| ConvertTo-Json -Depth 10)

        # API url definition
        $url = "/v2/network/interfaces/1/networks/$NetworkID"
        
        # API call run	
        try {
            $response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop

            # Response (Existing network configurations)
            $url = "/v2/network/interfaces/1/networks/"
            $DetailedResponse= Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

            if ($json) {
                return @($DetailedResponse) | ConvertTo-Json -Depth 10
            }
            else {
                return $DetailedResponse
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

function List-QQConnections {
<#
    .SYNOPSIS
        Get the list of SMB and NFS protocol connections per node
    .DESCRIPTION
        Return a list of NFS and SMB protocol connections to each node
    .EXAMPLE
        List-QQConnections [-Json]
    .LINK
        https://care.qumulo.com/hc/en-us/articles/115009003427--Balance-of-Client-Connections-on-your-Qumulo-Cluster-#details-0-2
    #>

    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json
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
        $url = "/v2/network/connections/"

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

function List-QQInterfaces {
<#
    .SYNOPSIS
        List configurations for interfaces on the cluster
    .DESCRIPTION
       Get configurations of all interfaces for the whole cluster.
    .EXAMPLE
        List-QQInterfaces [-Json]
    #>

    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json
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
        $url = "/v2/network/interfaces/"

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

function Get-QQInterface {
<#
    .SYNOPSIS
        Get configuration for the specified interface
    .DESCRIPTION
        Get configuration of an interface.
    .PARAMETER InterfaceID [ID]
        The unique ID of the network interface
    .EXAMPLE
        Get-QQNetwork -InterfaceID [ID] [-Json]
    #>

    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json,
        [Parameter(Mandatory = $True)][string]$InterfaceID
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
        $url = "/v2/network/interfaces/$InterfaceID"

        # API call run	
        try {
            $response= Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop

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

function Modify-QQInterface {
    <#
        .SYNOPSIS
            Modify interface configuration
        .DESCRIPTION
            Update a subset of an interface configuration. Changes in interface MTU will be applied to the untagged STATIC network as well as the interface.
        .PARAMETER InterfaceID    INTERFACE_ID
            The unique ID of the interface
        .PARAMETER DefaultGateway DEFAULT_GATEWAY
            The default IPv4 gateway address
        .PARAMETER DefaultGatewayIpv6 DEFAULT_GATEWAY_IPV6
            The default IPv6 gateway address
        .PARAMETER BondingMode    {ACTIVE_BACKUP,IEEE_8023AD}
            Ethernet bonding mode
        .PARAMETER Mtu MTU        
            The maximum transfer unit (MTU) in bytes of the interface and any untagged STATIC network.
        .EXAMPLE
            Modify-QQInterface [-Json] -InterfaceID INTERFACE_ID -DefaultGateway DEFAULT_GATEWAY -DefaultGatewayIpv6 DEFAULT_GATEWAY_IPV6 -BondingMode    {ACTIVE_BACKUP,IEEE_8023AD} -Mtu MTU
        #>

        # CmdletBinding parameters
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $False)][switch]$Json,
            [Parameter(Mandatory = $True)][string]$InterfaceID,
            [Parameter(Mandatory = $False)][string]$DefaultGateway,
            [Parameter(Mandatory = $False)][string]$DefaultGatewayIpv6,
            [Parameter(Mandatory = $False)][ValidateSet("Active_Backup","IEEE_8023AD")][string]$BondingMode,
            [Parameter(Mandatory = $False)][int16]$MTU
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
    
            # API Request Body
            $body = @{
                "id" = [int16]$InterfaceID
            }

            if($DefaultGateway){ $body += @{"default_gateway" = $DefaultGateway}}
            if($DefaultGatewayIpv6){ $body += @{"default_gateway_ipv6" = $DefaultGatewayIpv6}}
            if($BondingMode){ $body += @{"bonding_mode" = $BondingMode.ToUpper()}}
            if($MTU){ $body += @{"mtu" = $MTU}}

            Write-Debug($body| ConvertTo-Json -Depth 10)
    
            # API url definition
            $url = "/v2/network/interfaces/$InterfaceID"
            
            # API call run
            try {
                $response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -TimeoutSec 60 -ErrorAction:Stop
    
                # Response (Existing interface configurations)
                $url = "/v2/network/interfaces/"
                $DetailedResponse = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri "https://${clusterName}:$portNumber$url" -Headers $TokenHeader -ContentType "application/json" -TimeoutSec 60 -ErrorAction:Stop
    
                if ($json) {
                    return @($DetailedResponse) | ConvertTo-Json -Depth 10
                }
                else {
                    return $DetailedResponse
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


function List-QQNetworkPoll {
<#
    .SYNOPSIS
        Poll network status
    .DESCRIPTION
        Retrieve the network statuses of all nodes or of a specific on the underlying network interface
    .PARAMETER NodeID [ID]
        The unique ID of the node
    .EXAMPLE
        List-QQNetworkPoll[-Json]
    #>

    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json,
        [Parameter(Mandatory = $False)][string]$NodeID
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
        if($nodeID){
            $url = "/v2/network/interfaces/1/status/$nodeID"
        }
        else{
            $url = "/v2/network/interfaces/1/status/"
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

function Get-QQPersistentIps {
<#
    .SYNOPSIS
        Returns total/used/available numbers of IPs based on the current network configuration. 
    .DESCRIPTION
        Returns total/used/available numbers of IPs based on the current network configuration. 
    .EXAMPLE
        Get-QQPersistentIps [-Json]
    .LINK
        https://care.qumulo.com/hc/en-us/articles/115007237948-Connect-to-Multiple-Networks-in-Qumulo-Core
    #>

    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json
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
        $url = "/v1/network/static-ip-allocation"

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

function Get-QQFloatingIps {
<#
    .SYNOPSIS
        Returns floating IPs per node distribution based on the current network configuration. 
    .DESCRIPTION
        Returns floating IPs per node distribution based on the current network configuration. 
    .EXAMPLE
        Get-QQFloatingIps [-Json]
    .LINK
        https://care.qumulo.com/hc/en-us/articles/115007237948-Connect-to-Multiple-Networks-in-Qumulo-Core
    #>

    # CmdletBinding parameters
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)][switch]$Json
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
        $url = "/v1/network/floating-ip-allocation"

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