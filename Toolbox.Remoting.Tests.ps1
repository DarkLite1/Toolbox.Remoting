#Requires -Modules Pester
#Requires -Version 5.1

BeforeDiscovery {
    # used by inModuleScope
    $testModule = $PSCommandPath.Replace('.Tests.ps1', '.psm1')
    $testModuleName = $testModule.Split('\')[-1].TrimEnd('.psm1')

    Remove-Module $testModuleName -Force -Verbose:$false -EA Ignore
    Import-Module $testModule -Force -Verbose:$false
}
Describe 'Optimize-ExecutionOrderHC' {
    Context 'throws a terminating error when' {
        It 'the property ComputerName is missing' {
            { Optimize-ExecutionOrderHC -Name @(@{Name = 1 }) } | 
            Should -Throw
        } 
    }
    Context 'orders objects based on ComputerName correctly when' {
        It 'only 1 object is provided' {
            $testData = [PSCustomObject]@{Name = 'a'; ComputerName = '1' }
            
            $Actual = Optimize-ExecutionOrderHC -Name $testData

            $testData[0] | Should -Be $Actual[0]
        } 
        It 'only 2 different objects are provided' {
            $testData = @(
                [PSCustomObject]@{Name = 'a'; ComputerName = '1' }
                [PSCustomObject]@{Name = 'b'; ComputerName = '2' }
            )
            
            $Actual = Optimize-ExecutionOrderHC -Name $testData

            $testData[0] | Should -Be $Actual[0]
            $testData[1] | Should -Be $Actual[1]
        } 
        It '3 different objects are provided in the wrong order' {
            $testData = @(
                [PSCustomObject]@{Name = 'a'; ComputerName = '1' }
                [PSCustomObject]@{Name = 'b'; ComputerName = '1' }
                [PSCustomObject]@{Name = 'c'; ComputerName = '2' }
            )
            
            $Actual = Optimize-ExecutionOrderHC -Name $testData

            $testData[0] | Should -Be $Actual[0]
            $testData[1] | Should -Be $Actual[2]
            $testData[2] | Should -Be $Actual[1]
        } 
        It 'multiple different objects are provided in the wrong order' {
            $testData = @(
                [PSCustomObject]@{Name = 'a'; ComputerName = '1' }
                [PSCustomObject]@{Name = 'b'; ComputerName = '1' }
                [PSCustomObject]@{Name = 'c'; ComputerName = '1' }
                [PSCustomObject]@{Name = 'd'; ComputerName = '2' }
                [PSCustomObject]@{Name = 'e'; ComputerName = '2' }
                [PSCustomObject]@{Name = 'f'; ComputerName = '2' }
                [PSCustomObject]@{Name = 'g'; ComputerName = '3' }
                [PSCustomObject]@{Name = 'h'; ComputerName = '3' }
                [PSCustomObject]@{Name = 'i'; ComputerName = '4' }
            )
            
            $Actual = Optimize-ExecutionOrderHC -Name $testData

            $testData[0] | Should -Be $Actual[0]
            $testData[1] | Should -Be $Actual[4]
            $testData[2] | Should -Be $Actual[7]
            $testData[3] | Should -Be $Actual[1]
            $testData[4] | Should -Be $Actual[5]
            $testData[5] | Should -Be $Actual[8]
            $testData[6] | Should -Be $Actual[2]
            $testData[7] | Should -Be $Actual[6]
            $testData[8] | Should -Be $Actual[3]
        } 
    }
} -Skip
