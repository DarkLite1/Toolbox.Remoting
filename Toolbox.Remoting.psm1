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

Function New-CimSessionHC {
    <#
    .SYNOPSIS
        Creates CimSessions to remote computer(s), automatically determining if the WsMan
        or DCOM protocol should be used.

    .DESCRIPTION
        New-MrCimSession is a function that is designed to create CimSessions to one or more
        computers, automatically determining if the default WsMan protocol or the backwards
        compatible DCOM protocol should be used. PowerShell version 3 is required on the
        computer that this function is being run on, but PowerShell does not need to be
        installed at all on the remote computer.

    .PARAMETER ComputerName
        The name of the remote computer(s). This parameter accepts pipeline input. The local
        computer is the default.

    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is
        the current user.

    .EXAMPLE
        New-MrCimSessionHC -ComputerName Server01, Server02

    .EXAMPLE
        New-MrCimSessionHC -ComputerName Server01, Server02 -Credential (Get-Credential)

    .EXAMPLE
        Get-Content -Path C:\Servers.txt | New-MrCimSessionHC

    .INPUTS
        String

    .OUTPUTS
        Microsoft.Management.Infrastructure.CimSession

    .NOTES
        Author:  Mike F Robbins
        Website: http://mikefrobbins.com
        Twitter: @mikefrobbins
#>
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [String[]]$ComputerName = $env:COMPUTERNAME,
        [PSCredential]$Credential
        #[System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
    )
 
    BEGIN {
        $Opt = New-CimSessionOption -Protocol Dcom
 
        $SessionParams = @{
            ErrorAction = 'Stop'
        }
 
        If ($PSBoundParameters['Credential']) {
            $SessionParams.Credential = $Credential
        }
    }
 
    PROCESS {
        foreach ($Computer in $ComputerName) {
            $SessionParams.ComputerName = $Computer
 
            if ((Test-WSMan -ComputerName $Computer -ErrorAction SilentlyContinue).productversion -match 'Stack: ([3-9]|[1-9][0-9]+)\.[0-9]+') {
                try {
                    Write-Verbose -Message "Attempting to connect to $Computer using the WSMAN protocol."
                    New-CimSession @SessionParams
                }
                catch {
                    throw "Unable to connect to $Computer using the WSMAN protocol. Verify your credentials and try again."
                }
            }
 
            else {
                $SessionParams.SessionOption = $Opt
 
                try {
                    Write-Verbose -Message "Attempting to connect to $Computer using the DCOM protocol."
                    New-CimSession @SessionParams
                }
                catch {
                    throw "Host '$Computer' is offline or hostname is incorrect."
                }
 
                $SessionParams.Remove('SessionOption')
            }            
        }
    }
}
Function Reset-SessionsHC {
    <# 
    .SYNOPSIS   
        Kill all open session.

    .DESCRIPTION
        When the maximum number of open sessions (5) has been reached, we can kill them but be 
        cautious as all open sessions will be killed.
    #>

    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $ComputerName
    )

    Process {
        (Get-WmiObject -Class win32_process -ComputerName $ComputerName | 
        Where-Object { $_.ProcessName -eq 'wsmprovhost.exe' } | 
        Select-Object -First 1).terminate()
    }
}
Function Set-RemoteSignedHC {
    <# 
    .SYNOPSIS   
        Set execution policy to 'RemoteSinged' on a remote server.

    .DESCRIPTION
        Set execution policy to 'RemoteSinged' on a remote server.
    #>

    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $ComputerName
    )

    Process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            powershell -command "& {Set-ExecutionPolicy RemoteSigned}"
        }
    }
}
Function Test-ConnectivityHC {
    Param (
        [Parameter(Mandatory)]
        [String]$ComputerName,
        [Parameter(Mandatory)]
        $Credential
    )
    if (-not(Test-Connection -ComputerName $ComputerName -Quiet)) {
        $Global:Error.Remove($Global:Error[0])
        throw "Host '$($ComputerName)' is offline or hostname is incorrect."
    }
    if ((Test-PsRemoting -ComputerName $ComputerName -Credential $Credential) -eq $false) {
        if (
            [Version](Get-WmiObject -Computer $ComputerName -Class Win32_OperatingSystem).Version -lt 
            [version]'6.0.0'
        ) {
            $Global:Error.Remove($Global:Error[0])
            throw "OS not supported on '$($ComputerName)', we need at least Windows 7 or Windows Server 2008."
        }
        else {
            $Global:Error.Remove($Global:Error[0])
            throw "Remoting failed on '$($ComputerName)', please enable PowerShell remoting and 'CredSSP' authentication."
        }
    }
}
Function Test-Port {	        
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
	        Test-Port -tcp 3389
	        Returns $True if the localhost is listening on 3389
	            
	    .EXAMPLE
	        Test-Port -tcp 3389 -ComputerName MyServer1
	        Returns $True if MyServer1 is listening on 3389
	            
	    .Notes #>
	    
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
            Write-Verbose " [Test-Port] :: Exception: $($_.exception.message)"
            return $false
        }
        catch {
            Write-Verbose " [Test-Port] :: General Exception"
            return $false
        }
	    
        if (!$wait) {
            $tcpClient.Close()
            Write-Verbose " [Test-Port] :: Connection Timeout"
            return $false
        }
        else {
            $null = $tcpclient.EndConnect($iar)
            $tcpclient.Close()
            $true
        }
    }
}
Function Test-PsRemoting {
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
        Test-PsRemoting -ComputerName <ComputerName>
        Returns true when PS remoting is enabled or false when it's not

        ComputerName: <ComputerName>
        Enabled:      True

    .EXAMPLE
        Test-PsRemoting -ComputerName PC1 -Credential (Get-Credential -Message 
        'Enter credentials' -UserName 'CONTOSO.NET\bob') -Authentication CredSSP
        
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
        [Int]$FreeMemory = 1GB
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