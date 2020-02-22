function Stop-NamedProcess {
  Param(
      [parameter(Mandatory=$true)]
      [String] $processName
  )
    Get-Process | Where-Object Name -Like "*$processName*" | Stop-Process -Force
}

function Connect-CdhVm {
    Param(
	    [parameter(Mandatory=$true)] [ValidateSet("dev","sit","uat","prod")][String] $Environment,
	    [parameter(Mandatory=$true)] [ValidateSet("mule","onto","mtls")] [String] $HostName
    )

    $baseHost = switch($hostName) {
	    "mule" { "muleworker" }
	    "onto" { "ontoserver" }
	    "mtls" { "mtls" }
	}
    $userName = switch($hostName) {
	    "mule" { "muleuser" }
	    "onto" { "ontouser" }
	    "mtls" { "mtlsuser" }
	}

    $keyPath = "${ENV:APPDATA}\cdhkeys\${environment}-${baseHost}.key"
    if (-Not (Test-Path $keyPath)) {
	Write-Host -ForegroundColor Yellow "Fetching private key from Key Vault..."
	    if (-Not (Test-Path "${ENV:APPDATA}\cdhkeys")) {
		Write-Host -ForegroundColor Yellow "Creating key cache..."
		New-Item -Path "${ENV:APPDATA}\cdhkeys" -ItemType Directory | Out-Null
	    }
	az keyvault secret download --vault-name "ncdhc-${environment}-1" --name "ncdhc-${environment}-${baseHost}-key" --file $keyPath
    } else {
	Write-Host -ForegroundColor Yellow "Using cached key $keyPath"
    }
    $fullhostname = "${userName}@ncdhc-${environment}-${baseHost}.australiaeast.cloudapp.azure.com"
    Write-Host -ForegroundColor Green "Connecting to $fullhostname..."
    Start-Process -FilePath ssh.exe -ArgumentList "-i", $keyPath, $fullhostname -NoNewWindow -Wait
}

function Get-MyIPAddress {
    (Invoke-WebRequest https://api.ipify.org?format=json | convertfrom-json).ip
}

New-Alias vi -Value nvim
