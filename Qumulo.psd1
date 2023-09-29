#
# Module manifest for module 'Qumulo'
#
# Generated by: Berat Ulualan
#
# Generated on: 8/19/2022
#

@{

	# Script module or binary module file associated with this manifest.
	RootModule = 'Qumulo.psm1'

	# Version number of this module.
	ModuleVersion = '6.2.2'

	# Supported PSEditions
	# CompatiblePSEditions = @()

	# ID used to uniquely identify this module
	GUID = 'dedd5522-5ec6-49e2-86c8-e56f453d5470'

	# Author of this module
	Author = 'Berat Ulualan'

	# Company or vendor of this module
	CompanyName = 'Qumulo, Inc.'

	# Copyright statement for this module
	Copyright = '(c) 2023 Qumulo, Inc. All rights reserved.'

	# Description of the functionality provided by this module
	Description = 'Qumulo Powershell Toolkit will help the Qumulo customers who uses Microsoft PowerShell for their daily operations.'

	# Minimum version of the PowerShell engine required by this module
	PowerShellVersion = '7.2'

	# Name of the PowerShell host required by this module
	# PowerShellHostName = ''

	# Minimum version of the PowerShell host required by this module
	# PowerShellHostVersion = ''

	# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
	# DotNetFrameworkVersion = ''

	# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
	# ClrVersion = ''

	# Processor architecture (None, X86, Amd64) required by this module
	# ProcessorArchitecture = ''

	# Modules that must be imported into the global environment prior to importing this module
	# RequiredModules = @()

	# Assemblies that must be loaded prior to importing this module
	# RequiredAssemblies = @()

	# Script files (.ps1) that are run in the caller's environment prior to importing this module.
	ScriptsToProcess = 'QumuloHelp.ps1','QumuloSession.ps1','QumuloQuota.ps1',
	'QumuloShift.ps1','QumuloSnapshot.ps1','QumuloCluster.ps1',
	'QumuloSMB.ps1','QumuloNetwork.ps1','QumuloAudit.ps1',
	'QumuloTime.ps1','QumuloActiveDirectory.ps1','QumuloMonitoring.ps1',
	'QumuloFileSystem.ps1','QumuloRoles.ps1','QumuloFTP.ps1','QumuloFile.ps1',
	'QumuloNFS.ps1','QumuloReplication.ps1','QumuloAccessToken.ps1','QumuloAnalytics.ps1',
	'QumuloLocalUsers.ps1','QumuloLocalGroups.ps1','QumuloMultitenancy.ps1','QumuloRoles.ps1','QumuloShift.ps1',
	'QumuloTime.ps1','QumuloTreeDelete.ps1','QumuloUpgrades.ps1'

	# Type files (.ps1xml) to be loaded when importing this module
	# TypesToProcess = @()

	# Format files (.ps1xml) to be loaded when importing this module
	# FormatsToProcess = @()

	# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
	# NestedModules = @()

	# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
	FunctionsToExport = 'Get-QQHelp','Get-QQADSettings','Get-QQADStatus','Get-QQADMonitor',
	'Join-QQADDomain','Leave-QQADDomain','Cancel-QQADOperation',
	'Set-QQADSettings','Reconfigure-QQADDomain','Get-QQADDNToAccount',
	'Get-QQADUserSIDs','Get-QQADUIDtoSIDs','Get-QQADSIDtoUID','Get-QQADSIDtoUsername',
	'Get-QQADSIDtoGID','Get-QQADGIDtoSIDs','Get-QQADSIDtoExpandedGroupSIDs',
	'Get-QQSyslogConfig','Get-QQSyslogStatus','Set-QQSyslogConfig','Get-QQCloudWatchConfig',
	'Get-QQCloudWatchStatus','Set-QQCloudWatchConfig',
	'Get-QQClusterSettings','List-QQNodes','Get-QQNode','Get-QQUIDLightStatus','List-QQUnconfiguredNodes',
	'Get-QQEncryptionStatus','Get-QQNodeState','List-QQClusterSlots','Get-QQChassisStatus',
	'Get-QQProtectionStatus','Get-QQRestriperStatus','Get-QQVersion',
	'Get-QQSSLCaCertificate','Get-QQWebUISettings','Modify-QQWebUISettings','Resolve-QQFilePath',
	'List-QQNamedStreams','Get-QQFSStatistics','Get-QQMonitoringConfig',
	'List-QQMonitoringStatus','Get-QQVPNKeys','Get-QQMetrics','List-QQNetworks',
	'Get-QQNetwork','Add-QQNetwork','Delete-QQNetwork',
	'Modify-QQNetwork','List-QQConnections','List-QQInterfaces',
	'Get-QQInterface','Modify-QQInterface','List-QQNetworkPoll',
	'Get-QQPersistentIps','Get-QQFloatingIps','List-QQDirQuotas',
	'Get-QQDirQuota','Create-QQDirQuota','Update-QQDirQuota',
	'Delete-QQDirQuota','List-QQRoles','Get-QQRole','Get-QQRoleMembers',
	'Login-QQCluster','List-QQCurrentUser','List-QQCurrentRoles',
	'List-QQAllPrivileges','List-QQObjectRelationships',
	'List-QQObjectRelationshipStatuses','Get-QQObjectRelationship',
	'Get-QQObjectRelationshipStatus','Create-QQObjectRelationship',
	'Delete-QQObjectRelationship','Start-QQObjectRelationship',
	'Abort-QQObjectRelationship','List-QQSMBShares','List-QQSMBShare',
	'Add-QQSMBShare','Delete-QQSMBShare','Add-QQSMBSharePermission',
	'Remove-QQSMBSharePermission','Get-QQSMBSettings',
	'Modify-QQSMBSettings','List-QQSMBFileHandles','Close-QQSMBFileHandles',
	'List-QQSnapshots','List-QQSnapshotStatuses',
	'Get-QQSnapshot','Get-QQSnapshotStatus','Delete-QQSnapshot',
	'Create-QQSnapshot','Modify-QQSnapshot',
	'Get-QQSnapshotsCapacityUsage','Get-QQSnapshotCapacityUsage',
	'Get-QQSnapshotsAllCapacityUsage','Get-QQTime','Get-QQTimeStatus',
	'Set-QQTime','List-QQTimeZones','Get-QQFileAttr','Create-QQNewDir','Set-QQFileAttr',
	'Get-QQFileSamples','Read-QQDirAggregates','Read-QQDir',
	'Get-QQFTPStatus','Get-QQFTPSettings','Modify-QQFTPSettings ','Get-FSPermissisonSettings',
	'Get-QQFSAtimeSettings','Set-QQFSAtimeSettings','Get-QQFSNotifySettings','Set-QQFSNotifySettings',
	'Get-QQFileAcl','List-QQSourceRelationships','List-QQSourceRelationshipStatuses','Get-QQSourceRelationship',
	'Get-QQSourceRelationshipStatus','List-QQSourceRelationshipSnapshots',
	'List-QQTargetRelationshipStatuses','Get-QQTargetRelationshipStatus',
	'List-QQLocalUsers','Get-QQLocalUser','Get-QQLocalUserGroups',
	'Add-QQLocalUser','Delete-QQLocalUser','Set-QQUserPassword',
	'List-QQLocalGroups','Get-QQLocalGroup','Get-QQGroupMembers',
	'Add-QQLocalGroup','Delete-QQLocalGroup','Modify-QQLocalGroup',
	'List-QQTreeDeletes','Get-QQTreeDelete','Create-QQTreeDelete','Cancel-QQTreeDelete',
	'Get-QQTimeSeries','Get-QQCurrentActivity','Get-QQCapacityHistory','Get-QQFilesCapacityHistory',
	'List-QQAccessTokens','Get-QQAccessToken','Create-QQAccessToken','Modify-QQAccessToken','Verify-QQUgradeImage','Prepare-QQUgrade',
	'Delete-QQAccessToken','Commit-QQUgrade','Get-QQUpgradeStatus','List-QQTenants','Set-QQMultitenancy','Get-QQTenant',
	'Create-QQTenant','Delete-QQTenant',
	'List-NFSExports','Get-QQNFSExport','Delete-QQNFSExport','Add-QQNFSExport','Modify-QQNFSExport',
	'Add-QQNFSExportHostAccess','List-QQNFSExportHostAccess','Modify-QQNFSExportHostAccess','Remove-QQNFSExportHostAccess',
	'Get-QQNFSSettings','Modify-QQNFSSettings '

	# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
	CmdletsToExport = '*'

	# Variables to export from this module
	VariablesToExport = '*'

	# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
	AliasesToExport = '*'

	# DSC resources to export from this module
	# DscResourcesToExport = @()

	# List of all modules packaged with this module
	# ModuleList = @()

	# List of all files packaged with this module
	# FileList = @()

	# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData = @{

		PSData = @{

			# Tags applied to this module. These help with module discovery in online galleries.
			# Tags = @()

			# A URL to the license for this module.
			# LicenseUri = ''

			# A URL to the main website for this project.
			# ProjectUri = ''

			# A URL to an icon representing this module.
			# IconUri = ''

			# ReleaseNotes of this module
			ReleaseNotes = 'The toolkit has a bunch of Qumulo operations that will require mainly for Windows based clients and  will be expanded for whole CLI tool command set in the future.'

			# Prerelease string of this module
			# Prerelease = ''

			# Flag to indicate whether the module requires explicit user acceptance for install/update/save
			# RequireLicenseAcceptance = $false

			# External dependent modules of this module
			# ExternalModuleDependencies = @()

		} # End of PSData hashtable

	} # End of PrivateData hashtable

	# HelpInfo URI of this module
	HelpInfoURI = 'https://github.com/Qumulo/PowershellToolkit/issues'

	# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
	# DefaultCommandPrefix = ''

}

