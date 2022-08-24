# Qumulo PowerShell Toolkit

## Table of Contents

   * [Introduction](#introduction)
   * [Installation](#installation)
   * [Usage](#usage)
   * [Help](#help)
   * [Learn More](#learn-more)
   * [Copyright](#copyright)
   * [License](#license)
   * [Trademarks](#trademarks)
   * [Contributors](#contributors)

## Introduction

Qumulo Powershell Toolkit will help the Qumulo customers who uses Microsoft PowerShell for their daily operations.

The toolkit has a bunch of Qumulo operations that will require mainly for Windows based clients and this will expand for whole CLI tool command set in the future.

## Installation

### PowerShell Gallery

Run the following command in an elevated PowerShell session to install the rollup module for Qumulo cmdlets:

```powershell
Install-Module -Name Qumulo
```

This module runs on PowerShell 7 or greater version. [The latest version](https://github.com/PowerShell/PowerShell/releases/latest). 

If you have an earlier version of the Qumulo PowerShell modules installed from the PowerShell Gallery and would like to update to the latest version, run the following commands in an elevated PowerShell session:

```powershell
Update-Module -Name Qumulo
```

`Update-Module` installs the new version side-by-side with previous versions. It does not uninstall the previous versions.

## Usage

To connect to a Qumulo cluster, use the `Login-QQCluster` cmdlet:

```powershell
# Login a Qumulo cluster with your username and password
Login-QQCluster -ClusterName qumulo.best.filestorage.com -UserName admin -Password *********
```
### Discovering cmdlets

Use the `Get-Command` cmdlet to discover cmdlets within a specific module, or cmdlets that follow a specific search pattern:

```powershell
# List all cmdlets in the Qumulo module
Get-Command -Module Qumulo

# List all cmdlets that contain SMBShare
Get-Command -Name '*SMBShare*'

# List all cmdlets that contain SMB in the Qumulo module
Get-Command -Module Qumulo -Name '*SMB*'
```

### Cmdlet help and examples

To view the help content for a cmdlet, use the `Get-Help` cmdlet:

```powershell
# View the basic help content for List-QQSMBShare
Get-Help -Name List-QQSMBShare

# View the examples for List-QQSMBShare
Get-Help -Name List-QQSMBShare -Examples

# View the full help content for List-QQSMBShare
Get-Help -Name List-QQSMBShare -Full
```

To view the list of the QQ cmdlets, use the `Get-QQHelp` cmdlet:

```powershell
# View the list of the QQ cmdlets
Get-QQHelp
``` 

## Help

To post feedback, submit feature ideas, or report bugs, use the [Issues](https://github.com/Qumulo/PowershellToolkit/issues) section of this GitHub repo.

## Learn More

* [Qumulo Care](https://care.qumulo.com)

## Copyright

Copyright © 2022 [Qumulo, Inc.](https://qumulo.com)

## License

[![License](https://img.shields.io/badge/license-MIT-green)](https://opensource.org/licenses/MIT)

See [LICENSE](LICENSE) for full details

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

## Trademarks

All other trademarks referenced herein are the property of their respective owners.

## Contributors

 - [Berat Ulualan](https://github.com/beratulualan)
 - [Michael Kade](https://github.com/mikekade)

Date: August 19th, 2022 16:02 UTC
