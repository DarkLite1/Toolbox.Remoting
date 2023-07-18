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
	                        
	    .PARAMETER TCPPort 
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
        [int]$TCPport = 135,
        [Parameter()]
        [int]$TimeOut = 3000,
        [Parameter(ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [String]$ComputerName = $env:COMPUTERNAME
    )
	    
    Process {
        $tcpClient = New-Object system.Net.Sockets.TcpClient
	        
        try {
            $iar = $tcpClient.BeginConnect($ComputerName, $TCPport, $null, $null)
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

    .PARAMETER Name
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
            Wait-MaxRunningJobsHC -Name $jobs -MaxThreads 3
        }

        Only allow 3 jobs to run at the same time. Wait to launch the next
        job until one is finished.
    #>
    
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [System.Management.Automation.Job[]]$Name,
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
Workflow Get-PowerShellRemotingAndVersionHC {
    <# 
    .SYNOPSIS   
        Retrieve the PowerShell configuration of clients.

    .DESCRIPTION
        Retrieve the PowerShell configuration of clients: PSVersion, 
        WSManVersion, PSRemoting, OSVersion

    .PARAMETER ComputerName 
        If not provided we check all servers.

    .EXAMPLE
        $params = @{
            Credentials  = Get-Credential
            ComputerName = PC1
        }
        $Result = Get-PowerShellRemotingAndVersionHC @params

        Check the PowerShell capabilities of PC1
    #>

    [CmdletBinding()]
    Param ( 
        [Parameter(Mandatory)]
        [String[]]$ComputerName,
        [Parameter(Mandatory)]
        [PSCredential]$Credentials
    )

    Foreach -parallel ($C in $ComputerName) {
        Write-Verbose "ComputerName '$C'"
        Sequence {
            Function Get-OsInfoHC {
                Param (
                    [String]$ComputerName,
                    [PSCredential]$Credentials
                )
                $OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -Credential $Credentials -EA Stop
                $OSCap = $OS.Caption
                $OSArch = $OS.OSArchitecture
                $OSType = $OS.OtherTypeDescription
                $OSCDSV = $OS.CSDVersion
				
                if (-not $OSArch) {
                    $OSFullName = "$OSCap $OSType 32-bit $OSCDSV"
                }
                else {
                    $OSFullName = "$OSCap $OSType $OSArch $OSCDSV".Replace('  ', '')
                }
				
                $LBTime = $OS.ConvertToDateTime($OS.Lastbootuptime)
                $Uptime = New-TimeSpan $LBTime $(Get-Date)
                $OSInstall = [Management.ManagementDateTimeConverter]::ToDateTime($OS.InstallDate)
                $OSInstallDate = "$($OSInstall.Day)/$($OSInstall.Month)/$($OSInstall.Year)"
        
                [PSCustomObject]@{
                    OS          = $OSFullName
                    UpTime      = $Uptime
                    InstallDate = $OSInstallDate
                }
            }

            Try {
                if (Test-Connection $C -Count 3 -Quiet) {
                    $Online = $true

                    Try {
                        $OS = Get-OsInfoHC -ComputerName $C -Credential $Credentials
                        $WMIQuerySupport = $true
                    }
                    Catch {
                        $WMIQuerySupport = "Couldn't retrieve WMI for '$C': $($_.Message)"
                    }

                    $Remoting = InlineScript {
                        $C = $Using:C
                        Try {
                            $Max1 = Get-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB -EA Stop | 
                            Select-Object -ExpandProperty Value  
                            $Max2 = Get-Item WSMan:\localhost\Plugin\Microsoft.PowerShell\Quotas\MaxMemoryPerShellMB -EA Stop | 
                            Select-Object -ExpandProperty Value
                        } 
                        Catch {
                            $Error.Remove($Error[0])
                        }
                        New-Object PSObject -Property @{
                            Test            = 1
                            PSVersion       = '{0}.{1}' -f ($PSVersionTable.PSVersion).Major, ($PSVersionTable.PSVersion).Minor
                            WSManVersion    = '{0}.{1}' -f ($PSVersionTable.WSManStackVersion).Major, ($PSVersionTable.WSManStackVersion).Minor
                            MaxMemPerShell  = $Max1
                            MaxMemPerPlugin = $Max2
                        }
                  
                    } -PSComputerName $C -PSCredential $Credentials

                    if ($Remoting.Test -eq 1) {
                        $Credssp = InlineScript { 1 } -PSComputerName "$C.$env:USERDNSDOMAIN" -PSCredential $Credentials -PSAuthentication 'Credssp'
                    }
                }
                else {
                    $Online = $false
                }
            }
            Catch {
                $Prob = $_.Message
            }

            [PSCustomObject]@{
                ComputerName    = $C
                Online          = $Online
                WMIQuerySupport = $WMIQuerySupport
                Remoting        = if ($Online) { if ($Remoting.Test -eq 1) { $true } else { $false } };
                Credssp         = if ($Remoting.Test -eq 1 -and $Online) { if ($CredSsp -eq 1) { $true } else { $false } };
                MaxMemPerShell  = $Remoting.MaxMemPerShell
                MaxMemPerPlugin = $Remoting.MaxMemPerPlugin
                OS              = $OS.OS
                Uptime          = $OS.Uptime
                InstallDate     = $OS.InstallDate
                PSVersion       = $Remoting.PSVersion
                WSManVersion    = $Remoting.WSManVersion
                Error           = if ($Prob) { $Prob }
            }
            $Prob = $null
        }
    }
}

Export-ModuleMember -Function * -Alias *