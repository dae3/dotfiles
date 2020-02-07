function Stop-NamedProcess {
  Param(
      [parameter(Mandatory=$true)]
      [String] $processName
  )
    Get-Process | Where-Object Name -Like "*$processName*" | Stop-Process -Force
}

# just a test
