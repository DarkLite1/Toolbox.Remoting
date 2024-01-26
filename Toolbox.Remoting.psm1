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
Function New-PSSessionHC {
    <#
        .SYNOPSIS
            Use the latest version of PowerShell on the remote machine.

        .DESCRIPTION
            Return a PowerShell session object that can be used with
            remoting CmdLets like Invoke-Command to establish a remote
            connection with the latest version of PowerShell.

        .PARAMETER LogFolder
            Save a list of clients that do not support the PowerShell version
            defined in PowerShellEndpointVersion.

        .EXAMPLE
            Get-PSSessionConfiguration

            $computerName = $env:COMPUTERNAME

            try {
                $invokeParams = @{
                    Session      = New-PSSessionHC -ComputerName $computerName
                    ScriptBlock  = {
                        ($PSVersionTable).PSVersion.ToString()
                    }
                    ArgumentList = $Path
                    asJob        = $true
                }

                $job = Invoke-Command @invokeParams

                $job | Wait-Job | Receive-Job
            }
            catch {
                throw "Failed running Invoke-Command: $_"
            }


             Find out which PowerShell versions are enabled on the local
             machine for accepting remote connections.

             Then try to create a PowerShell session tin the latest PowerShell
             version installed.
    #>

    [OutputType([System.Management.Automation.RunSpaces.PSSession])]
    Param (
        [Parameter(Mandatory)]
        [String]$ComputerName,
        [String]$PowerShellEndpointVersion = 'PowerShell.7',
        [String]$LogFolder = 'T:\Test\Brecht\PowerShell'
    )

    try {
        $params = @{
            ComputerName      = $computerName
            ConfigurationName = $PowerShellEndpointVersion
            ErrorAction       = 'Stop'
        }
        New-PSSession @params
    }
    catch {
        $global:Error.RemoveAt(0)

        Write-Verbose "PowerShellEndpointVersion '$PowerShellEndpointVersion' not supported on '$ComputerName'"

        $params.Remove('ConfigurationName')
        New-PSSession @params

        #region Create log file for incompatible clients
        if (Test-Path -LiteralPath $LogFolder -PathType Container) {
            $params = @{
                Path      = $LogFolder
                ChildPath = $PowerShellEndpointVersion + ' not compatible clients ' + (Get-Date).ToString('yyyyMMdd') + '.csv'
            }
            $logFile = Join-Path @params

            @{
                Date         = Get-Date
                ComputerName = $ComputerName
            } | Export-Csv -Append -Path $logFile
        }
        #endregion
    }
}
Function Set-ComputerConfigurationHC {
    <#
        .SYNOPSIS
            Set the correct settings on a computer to be able run PowerShell
            scripts.

        .DESCRIPTION
            Set the following computer settings:
            - Enable PSRemoting
            - Set MaxMemoryPerShell

        .EXAMPLE
            Set-ComputerConfigurationHC PC1

            Set PC1 to allow PowerShell remoting and expand the memory.
        #>

    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory, ValueFromPipeline)]
        [String[]]$ComputerName,
        [String]$PSExec = 'C:\Program Files\WindowsPowerShell\Modules\PSTools\PsExec.exe'
    )

    Begin {
        Write-Verbose "Configure computers for PowerShell remoting"
    }

    Process {
        $PSRemotingTestedComputers = $ComputerName | Test-PsRemotingHC

        $PSRemotingTestedComputers | Where-Object { -not $_.Enabled } |
        ForEach-Object {
            if (Test-Connection $_.ComputerName -Quiet) {
                Write-Verbose "'$($_.ComputerName)' Enable PowerShell remoting"

                Start-Process -FilePath $PSExec -ArgumentList  "\\$($_.ComputerName) -s powershell Enable-PSRemoting -Force"

                $_.Enabled = $true
            }
            else {
                Write-Warning "$($_.ComputerName) is offline"
            }
        }

        $EnabledComputerNames = (
            $PSRemotingTestedComputers | Where-Object { $_.Enabled }
        ).ComputerName

        if ($EnabledComputerNames) {
            $Session = New-PSSession -ComputerName $EnabledComputerNames

            Invoke-Command -Session $Session -ScriptBlock {
                Try {
                    $VerbosePreference = $Using:VerbosePreference


                    $Result = [PSCustomObject]@{
                        ComputerName              = $ENV:COMPUTERNAME
                        PowerShellVersion         = $null
                        ExecutionPolicy           = $null
                        MaxMemoryPerShellMB       = $null
                        MaxMemoryPerShellMBPlugin = $null
                        OSname                    = $null
                        Status                    = $null
                        Action                    = @()
                        Error                     = $null
                    }

                    #region Get OS Name
                    $OS = Get-WmiObject -Class Win32_OperatingSystem
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

                    #region Test PowerShell version
                    # because version 2.0 fails for the rest of the ScriptBlock
                    $Result.PowerShellVersion = $PSVersionTable.PSVersion

                    if ($PSVersionTable.PSVersion.Major -lt 4) {
                        $Result.Status = 'Error'
                        $Result.Error = 'PowerShell version outdated'
                        $Result
                        Exit-PSSession
                    }
                    #endregion

                    #region Test Execution policy
                    if ((Get-ExecutionPolicy) -ne 'RemoteSigned') {
                        Set-ExecutionPolicy RemoteSigned -Force

                        $Result.Action += "Set execution policy to 'RemoteSigned'"
                        $Result.Status = 'Updated'
                    }

                    $Result.ExecutionPolicy = Get-ExecutionPolicy
                    #endregion

                    #region Test MaxMemoryPerShellMB
                    if (-not (Get-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB).Value -ge 2048) {
                        $null = Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 2048
                        $RestartWinRm = $true

                        $Result.Action += "Shell MaxMemoryPerShellMB set to 2048"
                        $Result.Status = 'Updated'
                    }

                    $Result.MaxMemoryPerShellMB = (Get-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB).Value


                    if (-not (Get-Item WSMan:\localhost\Plugin\Microsoft.PowerShell\Quotas\MaxMemoryPerShellMB).Value -ge 2048) {
                        $null = Set-Item WSMan:\localhost\Plugin\Microsoft.PowerShell\Quotas\MaxMemoryPerShellMB 2048
                        $RestartWinRm = $true

                        $Result.Action += "Shell MaxMemoryPerShellMB Plugin set to 2048"
                        $Result.Status = 'Updated'
                    }

                    $Result.MaxMemoryPerShellMBPlugin = (Get-Item WSMan:\localhost\Plugin\Microsoft.PowerShell\Quotas\MaxMemoryPerShellMB).Value

                    if ($RestartWinRm) {
                        $null = Restart-Service winrm
                        $Result.Action += "Restarted WinRM service"
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
                    $Result.Error = $_

                    Write-Warning "'$ENV:COMPUTERNAME': $_"
                }
                Finally {
                    $Result
                }
            }
        }
    }

    End {
        Get-PSSession | Remove-PSSession
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
        [String]$Authentication
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
            (Get-WmiObject win32_OperatingSystem).FreePhysicalMemory * 1KB
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