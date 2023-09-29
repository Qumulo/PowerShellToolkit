<#
	===========================================================================
	Created by:   	berat.ulualan@qumulo.com
	Organization: 	Qumulo, Inc.
	Filename:     	Qumulo.psm1
	Module Name: 	Qumulo
	Description: 	PowerShell Script Module (.psm1)
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

# Qumulo help
Import-Module -Name ($PSScriptRoot + "\QumuloHelp.ps1") -WarningAction SilentlyContinue -Force

# Qumulo 
Import-Module -Name ($PSScriptRoot + "\QumuloSession.ps1") -WarningAction SilentlyContinue -Force

# Qumulo access token functions
Import-Module -Name ($PSScriptRoot + "\QumuloAccessToken.ps1") -WarningAction SilentlyContinue -Force

# Qumulo directory functions
Import-Module -Name ($PSScriptRoot + "\QumuloQuota.ps1") -WarningAction SilentlyContinue -Force

# Qumulo object-based replication to AWS S3 buckets (SHIFT) functions
Import-Module -Name ($PSScriptRoot + "\QumuloShift.ps1") -WarningAction SilentlyContinue -Force

# Qumulo snapshot functions
Import-Module -Name ($PSScriptRoot + "\QumuloSnapshot.ps1") -WarningAction SilentlyContinue -Force

# Qumulo functions of cluster level details and operations 
Import-Module -Name ($PSScriptRoot + "\QumuloCluster.ps1") -WarningAction SilentlyContinue -Force

# Qumulo SMB functions
Import-Module -Name ($PSScriptRoot + "\QumuloSMB.ps1") -WarningAction SilentlyContinue -Force

# Qumulo network functions
Import-Module -Name ($PSScriptRoot + "\QumuloNetwork.ps1") -WarningAction SilentlyContinue -Force

# Qumulo auditing functions
Import-Module -Name ($PSScriptRoot + "\QumuloAudit.ps1") -WarningAction SilentlyContinue -Force

# Qumulo date & time functions
Import-Module -Name ($PSScriptRoot + "\QumuloTime.ps1") -WarningAction SilentlyContinue -Force

# Qumulo active directoy functions
Import-Module -Name ($PSScriptRoot + "\QumuloActiveDirectory.ps1") -WarningAction SilentlyContinue -Force

# Qumulo monitoring functions
Import-Module -Name ($PSScriptRoot + "\QumuloMonitoring.ps1") -WarningAction SilentlyContinue -Force

# Qumulo file system functions
Import-Module -Name ($PSScriptRoot + "\QumuloFileSystem.ps1") -WarningAction SilentlyContinue -Force

# Qumulo role functions
Import-Module -Name ($PSScriptRoot + "\QumuloRoles.ps1") -WarningAction SilentlyContinue -Force

# Qumulo FTP functions
Import-Module -Name ($PSScriptRoot + "\QumuloFTP.ps1") -WarningAction SilentlyContinue -Force

# Qumulo File functions
Import-Module -Name ($PSScriptRoot + "\QumuloFile.ps1") -WarningAction SilentlyContinue -Force

# Qumulo Replication functions
Import-Module -Name ($PSScriptRoot + "\QumuloReplication.ps1") -WarningAction SilentlyContinue -Force

# Qumulo local users functions
Import-Module -Name ($PSScriptRoot + "\QumuloLocalUsers.ps1") -WarningAction SilentlyContinue -Force

# Qumulo local groups functions
Import-Module -Name ($PSScriptRoot + "\QumuloLocalGroups.ps1") -WarningAction SilentlyContinue -Force

# Qumulo directory delete functions
Import-Module -Name ($PSScriptRoot + "\QumuloTreeDelete.ps1") -WarningAction SilentlyContinue -Force

# Qumulo analytics functions
Import-Module -Name ($PSScriptRoot + "\QumuloAnalytics.ps1") -WarningAction SilentlyContinue -Force

# Qumulo upgrade functions
Import-Module -Name ($PSScriptRoot + "\QumuloUpgrades.ps1") -WarningAction SilentlyContinue -Force

# Qumulo multitenancy functions
Import-Module -Name ($PSScriptRoot + "\QumuloMultitenancy.ps1") -WarningAction SilentlyContinue -Force

# Qumulo NFS functions
Import-Module -Name ($PSScriptRoot + "\QumuloNFS.ps1") -WarningAction SilentlyContinue -Force
