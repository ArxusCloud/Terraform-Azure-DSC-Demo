configuration timezone {
    Import-DscResource -ModuleName ComputerManagementDsc

    TimeZone westeustandard {
        IsSingleInstance = 'Yes'
        TimeZone = 'W. Europe Standard Time'
    }
}
timezone