configuration timezone {
    Import-DscResource -ModuleName ComputerManagementDsc -ModuleVersion 5.0.0.0

    TimeZone westeustandard {
        IsSingleInstance = 'Yes'
        TimeZone = 'W. Europe Standard Time'
    }
}
timezone