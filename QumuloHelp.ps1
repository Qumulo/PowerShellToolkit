<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	QumuloHelp.ps1
	Module Name: 	Qumulo
	Description: 	PowerShell Script (.ps1) for Qumulo Powershell Toolkit commands and their details.
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
function Get-QQHelp {
    <#
        .SYNOPSIS
            Retrieve Qumulo Powershell Toolkit commands and their details.
        .DESCRIPTION
            Retrieve Qumulo Powershell Toolkit commands and their details.
        .EXAMPLE
            Get-QQHelp
    #>
    Write-Host "
    Active Directory
        Get-QQADSettings - Get advanced Active Directory settings
        Get-QQADStatus - Get Active Directory configuration and status.
        Get-QQADMonitor - Get details on a join or leave operation
        Join-QQADDomain - Join an Active Directory Domain
        Leave-QQADDomain - Removes the cluster from Active Directory.
        Cancel-QQADOperation - Cancel current join or leave operation.
        Set-QQADSettings - Modify advanced Active Directory settings
        Reconfigure-QQADDomain - Reconfigure Active Directory POSIX Attributes
        Get-QQADDNToAccount - Get all account info for a distinguished name
        Get-QQADUserSIDs - Get all account info for a distinguished name
        Get-QQADUIDtoSIDs - Get SIDs from UID
        Get-QQADSIDtoUID - Get UID from SID
        Get-QQADSIDtoUsername - Get AD username from SID
        Get-QQADSIDtoGID - Get GID from SID
        Get-QQADGIDtoSIDs - Get SIDs from GID
        Get-QQADSIDtoExpandedGroupSIDs  -  Get SID to Expanded Group SIDs

    Audit Logs
        Get-QQSyslogConfig - Get audit syslog server configuration
        Get-QQSyslogStatus - Get audit syslog server status
        Set-QQSyslogConfig - Set audit syslog server configuration
        Get-QQCloudWatchConfig - Get audit CloudWatch configuration
        Get-QQCloudWatchStatus - Get audit CloudWatch status
        Set-QQCloudWatchConfig - Set audit CloudWatch configuration

    Cluster
        Get-QQClusterSettings - Get the cluster config
        List-QQNodes -  List nodes or a node details
        List-QQUnconfiguredNodes - List unconfigured nodes
        Get-QQEncryptionStatus - View the status of encryption at rest
        Get-QQNodeState - Get the operational state of the node
        List-QQClusterSlots - List slots or retrieve info about the disk slot, such as its capacity, type, model, etc.
        Get-QQChassisStatus - Get the status of node chassis
        Get-QQProtectionStatus - Get detailed status information for the data protection of the cluster.
        Get-QQRestriperStatus - Get current status of restriper, including data protection status and current restripe phase (if running).
        Get-QQVersion - Retrieve the version of the appliance.
        Get-QQSSLCaCertificate - Get SSL CA certificate.

    Tree Delete
        Create-QQTreeDelete - Delete Directory Tree
        List-QQTreeDeletes - Tree Delete Job Statuses
        Get-QQTreeDelete - Status of Directory Tree Deletion
        Cancel-QQTreeDelete - Cancel a Tree Delete Job

    Analytics
        Get-QQTimeSeries - Get Time Series Statistics
        Get-QQCurrentActivity - Get the current sampled IOP and throughput rates
        Get-QQCapacityHistory - Get Capacity Usage History for a Time Window
        Get-QQFilesCapacityHistory - Get historical largest file data.

    FTP 
        Get-QQFTPStatus - Get FTP server status
        Get-QQFTPSettings - Get FTP server settings
        Modify-QQFTPSettings  - Set FTP server settings
    
    Files
        Get-QQFileAttr - Retrieve file attributes
        Get-QQFileAcl  - Retrieve file ACL
        Create-QQNewDir - Create a new directory 
        Set-QQFileAttr - Set file attributes
        Get-QQFileSamples - Get a number of sample files from the file system

    File System
        Get-QQFileSystemStatistics - Retrieve general file system statistics.
        Get-QQFSPermissionSettings - Get permissions settings.
        Set-QQFSPermissionSettings - Set permissions settings.
        Get-QQFSAtimeSettings - Get access time (atime) settings.
        Set-QQFSAtimeSettings - Set access time (atime) settings.

    Monitoring
        Get-QQMonitoringConfig - Get monitoring configuration.,
        List-QQMonitoringStatus - List the monitoring status of all nodes: whether various kinds of monitoring connections are enabled/connected/etc.
        Get-QQVPNKeys - Get VPN keys.

    Networking
        List-QQNetworks - List network configurations
        Get-QQNetwork - Get configuration for the specified network
        Add-QQNetwork - Add network configuration
        Delete-QQNetwork - Delete network configuration
        Modify-QQNetwork - Modify a network configuration
        List-QQConnections - Get the list of SMB and NFS protocol connections per node
        List-QQInterfaces - List configurations for interfaces on the cluster
        Get-QQInterface - Get configuration for the specified interface
        Modify-QQInterface - Modify interface configuration
        List-QQNetworkPoll - Retrieve the network statuses of all nodes or of a specific on the underlying network interface
        Get-QQPersistentIps - Returns total/used/available numbers of IPs based on the current network configuration. 
        Get-QQFloatingIps - Returns floating IPs per node distribution based on the current network configuration. 

    Quotas
        List-QQDirQuotas - List all directory quotas
        Get-QQDirQuota - Get the directory quota for a directory, its limit in bytes, and current capacity usage.
        Create-QQDirQuota - Create a directory quota
        Update-QQDirQuota - Update a directory quota
        Delete-QQDirQuota - Delete a directory quota

    Roles
        List-QQRoles - List all roles.
        Get-QQRole - Retrieve information about the role.
        Get-QQRoleMembers - List all members of a role.

    Session
        Login-QQCluster - Log in to Qumulo to get REST credentials
        List-QQCurrentUser - Get information on the current user
        List-QQCurrentRoles - List all of the roles.
        List-QQAllPrivileges - Get information about all privileges.
    
    Users
        List-QQLocalUsers - List all local users.
        Get-QQLocalUser - Get a local user's details.
        Get-QQLocalUserGroups - Get a local user's group details.
        Add-QQLocalUser - Add a new user
        Delete-QQLocalUser - Delete a new user
        Set-QQUserPassword - Set a user's password

    Groups
        List-QQLocalGroups - List all local groups.
        Get-QQLocalGroup - Get a local  group's details.
        Get-QQGroupMembers - Get group members
        Add-QQLocalGroup - Add a new group
        Delete-QQLocalGroup - Delete a new group
        Modify-QQLocalGroup - Modify a group

    Replication Relationship (SHIFT)
        List-QQSourceRelationships - List existing source replication relationships.
        List-QQSourceRelationshipStatuses - List statuses for all existing source replication relationship statuses.
        Get-QQSourceRelationship - Get information about the specified source replication relationship.
        Get-QQSourceRelationshipStatus - Get the status of an existing source replication relationship status.
        List-QQSourceRelationshipSnapshots - List All Queued Snapshots for a Source Relationship.
        List-QQTargetRelationshipStatuses - List statuses for all existing target replication relationship statuses.
        Get-QQTargetRelationshipStatus - Get the status of an existing target replication relationship status.

    Object Relationship (SHIFT)
        List-QQObjectRelationships - List existing object replication relationships.
        List-QQObjectRelationshipStatuses - List statuses for all existing object replication relationships.
        Get-QQObjectRelationship - Get information about the specified object replication relationship.
        Get-QQObjectRelationshipStatus - Get the status of an existing object replication relationship.
        Create-QQObjectRelationship - Create a new object replication relationship. Replication will automatically start after the relationship is created.
        Delete-QQObjectRelationship - Delete the specified object replication relationship, which must not be running a job.
        Start-QQObjectRelationship - Start a new replication job for the specified object relationship
        Abort-QQObjectRelationship - Abort any ongoing replication job for the specified object replication relationship.

    SMB
        List-QQSMBShares - List all SMB shares
        List-QQSMBShare - List a SMB share
        Add-QQSMBShare - Add a new SMB share
        Delete-QQSMBShare - Delete a SMB share
        Add-QQSMBSharePermission - Add new SMB share permissions
        Remove-QQSMBSharePermission - Remove matched SMB share permissions
        Get-QQSMBSettings - Get SMB settings
        Modify-QQSMBSettings - Set SMB server settings
        List-QQSMBFileHandles - List SMB open file handles
        Close-QQSMBFileHandles - Force close a specified SMB file handle

    Snapshots
        List-QQSnapshots - List all snapshots
        List-QQSnapshotStatuses - List all snapshot statuses
        Get-QQSnapshot - Get a single snapshot.
        Get-QQSnapshotStatus - Get a snaphot status
        Delete-QQSnapshot - Delete a single snapshot.
        Create-QQSnapshot - Create a directory snapshot
        Modify-QQSnapshot - Modifies a snapshot.
        Get-QQSnapshotsCapacityUsage - Get the total space consumed by all snapshots.
        Get-QQSnapshotCapacityUsage - Get the approximate amount of space for each snapshot that would be reclaimed if that snapshot were deleted.
        Get-QQSnapshotsAllCapacityUsage - Returns approximate amount of space that would be reclaimed if all snapshots were deleted.

    Time Settings
        Get-QQTime - Get time configuration.
        Get-QQTimeStatus - Get time configuration status.
        Set-QQTime - Set time configuration.
        List-QQTimeZones - List timezones supported by Qumulo
        "
}