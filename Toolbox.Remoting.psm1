#Requires -Version 7

Param (
    [String[]]$PSConfigurationNames = @(
        'PowerShell.7.4.1',
        'PowerShell.7',
        'microsoft.powershell'
    )
)

Function Enable-PSRemotingHC {
    <#
        .SYNOPSIS
            Enable PS remoting on a remote computer
    #>

    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory, ValueFromPipeline)]
        [String[]]$ComputerName,
        [String]$PSExec = 'C:\Program Files\WindowsPowerShell\Modules\PSTools\PsExec.exe'
    )

    $computerName | ForEach-Object -Parallel {
        try {
            $computerName = $_
            Start-Process -FilePath $using:PSExec -ArgumentList "\\$computerName -s pwsh.exe Enable-PSRemoting -Force"
        }
        catch {
            throw "Failed to enable PS Remoting on '$computerName': $_"
        }
    }
}
Function Get-PortNumbersHC {
    <#
    .SYNOPSIS
        Get the open ports for a specific process.

    .DESCRIPTION
        Get the open ports for a specific process by using netstat.

    .EXAMPLE
        Get-PortNumbersHC -ProcessName 'Communicator' -Verbose
        Will give a list of all open ports for the process Communicator
    #>

    [CmdLetBinding()]
    Param (
        [String[]]$ProcessName
    )

    Process {
        foreach ($P in $ProcessName) {
            Try {
                Write-Verbose "Check for process '$P'"
                $Process = Get-Process -Name $P -EA Stop

                $Found = $false
                foreach ($I in $Process.Id) {
                    if ($R = netstat -ano | findstr $I) {
                        $R
                        $Found = $true
                    }
                }

                if (-not $Found) {
                    Write-Verbose "No open ports found for process '$P'"
                }
            }
            Catch {
                throw "Failed to get the open ports for process '$ProcessName': $_"
            }
        }
    }
}
Function Get-PowerShellEndpointsHC {
    <#
        .SYNOPSIS
            List the PowerShell remoting endpoints.

        .DESCRIPTION
            Get a list of enabled PowerShell endpoints on a remote computer.
            The list is ordered so the latest version will be the first item
            in the returned collection

            The returned strings represent a PowerShell remoting configuration
            name that can be used with other CmdLets like `Invoke-Command` with
            the parameter 'ConfigurationName'.

        .EXAMPLE
            $endpoints = Get-PowerShellEndpointsHC -ComputerName 'PC1'
            $params = @{
                ComputerName      = 'PC1'
                ConfigurationName = $endpoints[0]
                ScriptBlock       = { ($PSVersionTable).PSVersion.ToString() }
                ErrorAction       = 'Stop'
            }
            Invoke-Command @params

            Connect to the latest available PowerShell endpoint on 'PC1'
    #>

    [OutputType([String[]])]
    Param (
        [Parameter(Mandatory)]
        [String]$ComputerName
    )

    $params = @{
        ComputerName = $ComputerName
        ScriptBlock  = {
            Get-PSSessionConfiguration | Where-Object {
                ($_.Enabled) -and
                ($_.Name -ne 'microsoft.windows.servermanagerworkflows') -and
                ($_.Name -ne 'microsoft.powershell.workflow') -and
                ($_.Name -ne 'microsoft.powershell32')

            } |
            Sort-Object -Property 'Name' -Descending |
            Select-Object -ExpandProperty 'Name'
        }
        ErrorAction  = 'Stop'
    }
    [array]$endpoints = Invoke-Command @params

    $endpoints
}
Function Set-ComputerConfigurationHC {
    <#
        .SYNOPSIS
            Set the correct settings on a computer to be able run PowerShell
            scripts.

        .DESCRIPTION
            Set the correct WsMan settings

        .EXAMPLE
            Set-ComputerConfigurationHC PC1

            Set PC1 to allow PowerShell remoting and expand the memory.
        #>

    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory, ValueFromPipeline)]
        [String[]]$ComputerName,
        [String]$ConfigurationName = $PSConfigurationNames[0],
        [hashtable]$WsmanSettings = @{
            'WSMan:\localhost\Shell\MaxShellsPerUser'                                 = [Int32]::MaxValue
            'WSMan:\localhost\Shell\MaxMemoryPerShellMB'                              = [Int32]::MaxValue
            'WSMan:\localhost\Plugin\Microsoft.PowerShell\Quotas\MaxMemoryPerShellMB' = [Int32]::MaxValue
            'WSMan:\localhost\Plugin\PowerShell.7\Quotas\MaxShellsPerUser'            = [Int32]::MaxValue
            'WSMan:\localhost\Plugin\PowerShell.7.4.1\Quotas\MaxShellsPerUser'        = [Int32]::MaxValue
        }
    )

    Invoke-Command -ComputerName $ComputerName -ConfigurationName $ConfigurationName -ScriptBlock {
        Try {
            $VerbosePreference = $Using:VerbosePreference

            $Result = [PSCustomObject]@{
                ComputerName    = $ENV:COMPUTERNAME
                ExecutionPolicy = $null
                OSname          = $null
                Status          = $null
                Action          = @()
                Error           = @()
            }

            #region Get OS Name
            $OS = Get-CimInstance -Class Win32_OperatingSystem
            $OSCap = $OS.Caption
            $OSArch = $OS.OSArchitecture
            $OSType = $OS.OtherTypeDescription
            $OSCDSV = $OS.CSDVersion

            if (-not $OSArch) {
                $Result.OSname = "$OSCap $OSType 32-bit $OSCDSV"
            }
            else {
                $Result.OSname = "$OSCap $OSType $OSArch $OSCDSV".Replace('  ', '')
            }
            #endregion

            #region Test Execution policy
            if ((Get-ExecutionPolicy) -ne 'RemoteSigned') {
                Set-ExecutionPolicy 'RemoteSigned' -Force

                $Result.Action += "Set execution policy to 'RemoteSigned'"
                $Result.Status = 'Updated'
            }

            $Result.ExecutionPolicy = Get-ExecutionPolicy
            #endregion

            #region Set WsMan settings
            $restartWinRm = $false

            $WsmanSettings = $using:WsmanSettings
            $WsmanSettings.GetEnumerator().ForEach(
                {
                    try {
                        $path = $_.Key
                        $value = $_.Value

                        if ((Get-Item -Path $path).Value -ne $value) {
                            $null = Set-Item -Path $path -Value $value
                            $restartWinRm = $true

                            $Result.Action += "Set '$path' to '$value'"
                            $Result.Status = 'Updated'
                        }
                    }
                    catch {
                        $result.Error += "Failed to set '$path' to '$value': $_"
                        $Error.RemoveAt(0)
                    }
                }
            )
            #endregion

            #region Restart WinR<
            if ($restartWinRm) {
                $null = Restart-Service winrm
                $Result.Action += 'Restarted WinRM service'
            }
            #endregion

            if (-not $Result.Status) {
                $Result.Status = 'Ok'
                Write-Verbose "'$ENV:COMPUTERNAME': Correctly configured"
            }
            else {
                Write-Verbose "'$ENV:COMPUTERNAME': Updated configuration"
            }
        }
        Catch {
            $Result.Status = 'Error'
            $Result.Error += $_

            Write-Warning "'$ENV:COMPUTERNAME': $_"
        }
        Finally {
            if ($Result.Error) {
                $Result.Status = 'Error'
            }
            $Result
        }
    }
}
Function Test-PortHC {
    <#
	    .SYNOPSIS
	        Test a host to see if the specified port is open.

	    .DESCRIPTION
	        Test a host to see if the specified port is open.

	    .PARAMETER Port
	        Port to test

	    .PARAMETER Timeout
	        How long to wait (in milliseconds) for the TCP connection.

	    .PARAMETER ComputerName
	        Computer to test the port against.

	    .EXAMPLE
	        Test-PortHC -tcp 3389
	        Returns $True if the localhost is listening on 3389

	    .EXAMPLE
	        Test-PortHC -tcp 3389 -ComputerName PC1

	        Returns True if PC1 is listening on 3389
    #>

    [CmdLetBinding()]
    Param(
        [Parameter()]
        [Alias('TCPport')]
        [int]$Port = 135,
        [Parameter()]
        [int]$TimeOut = 3000,
        [Parameter(ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [String]$ComputerName = $env:COMPUTERNAME
    )

    Process {
        $tcpClient = New-Object system.Net.Sockets.TcpClient

        try {
            $iar = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
            $wait = $iar.AsyncWaitHandle.WaitOne($TimeOut, $false)
        }
        catch [System.Net.Sockets.SocketException] {
            Write-Verbose " [Test-PortHC] :: Exception: $($_.exception.message)"
            return $false
        }
        catch {
            Write-Verbose " [Test-PortHC] :: General Exception"
            return $false
        }

        if (!$wait) {
            $tcpClient.Close()
            Write-Verbose " [Test-PortHC] :: Connection Timeout"
            return $false
        }
        else {
            $null = $tcpclient.EndConnect($iar)
            $tcpclient.Close()
            $true
        }
    }
}
Function Test-PsRemotingHC {
    <#
    .SYNOPSIS
        Check if remoting is enabled on a remote computer.

    .DESCRIPTION
        Check if PowerShell remoting is enabled on a remote computer and
        return an object with the result.

    .PARAMETER ComputerName
        Hostname to check.

    .PARAMETER Authentication
        Type of authentication to use, like 'CredSSP'.

    .PARAMETER Credential
        PowerShell credential object used for authentication.

    .EXAMPLE
        Test-PsRemotingHC -ComputerName PC1
        Returns true when PS remoting is enabled or false when it's not

        ComputerName: PC1
        Enabled:      True

    .EXAMPLE
        $params = @{
            ComputerName   = 'PC1'
            Credential     = Get-Credential
            Authentication = 'CredSSP'
        }
        Test-PsRemotingHC @params

        Returns true when PS remoting is enabled on PC1 when using these
        credentials with the authentication method supplied or false when it's
        not
    #>

    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [String[]]$ComputerName,
        [PSCredential]$Credential,
        [ValidateSet('CredSSP', 'Basic', 'Default', 'Kerberos')]
        [String]$Authentication,
        [String]$ConfigurationName = $PSConfigurationNames[0]
    )

    Process {
        foreach ($C in $ComputerName) {
            Try {
                $InvokeParams = @{
                    ComputerName = $C
                    ErrorAction  = 'Stop'
                }

                $Result = [PSCustomObject]@{
                    ComputerName = $InvokeParams.ComputerName
                    Enabled      = $null
                }

                if ($Credential) {
                    $InvokeParams.Credential = $Credential
                }

                if ($Authentication) {
                    $InvokeParams.Authentication = $Authentication
                }

                if ($ConfigurationName) {
                    $InvokeParams.ConfigurationName = $ConfigurationName
                }

                $Test = Invoke-Command @InvokeParams -ScriptBlock { 1 }

                if ($Test -ne 1) {
                    throw 'Test result incorrect'
                }

                $Result.Enabled = $true
            }
            Catch {
                $Result.Enabled = $false
            }

            $Result
        }

    }
}
Function Wait-MaxRunningJobsHC {
    <#
    .SYNOPSIS
        Limit how many jobs can run at the same time

    .DESCRIPTION
        Only allow a specific quantity of jobs to run at the same time.
        Also wait for launching new jobs when there is not enough free
        memory.

    .PARAMETER Job
        Name of the variable holding the jobs returned by 'Start-Job' or
        'Invoke-Command -AsJob'.

    .PARAMETER MaxThreads
        The number of jobs that are allowed to run at the same time.

    .PARAMETER FreeMemory
        The amount of memory in GB that needs to be free before a new job
        is allowed to start.

    .EXAMPLE
        $jobs = @()

        $scriptBlock = {
            Write-Output 'do work'
            Start-Sleep -Seconds 30
        }

        foreach ($i in 1..20) {
            Write-Verbose "Start job $i"
            $jobs += Start-Job -ScriptBlock $ScriptBlock
            Wait-MaxRunningJobsHC -Job $jobs -MaxThreads 3
        }

        Only allow 3 jobs to run at the same time. Wait to launch the next
        job until one is finished.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [Alias('Name')]
        [System.Management.Automation.Job[]]$Job,
        [Parameter(Mandatory)]
        [Int]$MaxThreads,
        [Int]$FreeMemory = 500MB
    )

    Begin {
        Function Get-FreeMemoryHC {
            (Get-CimInstance win32_OperatingSystem).FreePhysicalMemory * 1KB
        }
        Function Get-RunningJobsHC {
            @($Name).Where( { $_.State -eq 'Running' })
        }
    }

    Process {
        while (
            ((Get-FreeMemoryHC) -lt $FreeMemory) -or
            ((Get-RunningJobsHC).Count -ge $MaxThreads)
        ) {
            $null = Wait-Job -Job $Name -Any
        }
    }
}

Export-ModuleMember -Function * -Alias *