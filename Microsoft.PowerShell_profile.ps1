function Stop-NamedProcess {
  Param(
      [parameter(Mandatory=$true)]
      [String] $processName
  )
    Get-Process | Where-Object Name -Like "*$processName*" | Stop-Process -Force
}

function Connect-CdhVm {
    Param(
	    [parameter(Mandatory=$true)] [ValidateSet("dev","sit","sit01","uat","prod")][String] $Environment,
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

New-Alias -Name tf -Value terraform
New-Alias -Name vi -Value nvim

Import-Module 'C:\tools\poshgit\dahlbyk-posh-git-9bda399\src\posh-git.psd1'

function Get-RandomPassword {(Invoke-WebRequest "https://www.random.org/passwords/?num=1&len=8&format=plain&rnd=new").content.Trim() }

function Start-Drone { aws ec2 start-instances --instance-ids $ENV:DRONE_INSTANCE_ID }
function Stop-Drone { aws ec2 stop-instances --instance-ids $ENV:DRONE_INSTANCE_ID }

function Get-TodayTasks { Get-Content $ENV:TODOTXT | Select-String -Pattern '^\([A-Z]\)' }

Set-PSReadLineOption -EditMode Vi

function Set-AzureAccount {
    Param([parameter(Mandatory=$true)] [ValidateSet("smc","cdh")][String] $Environment)

    $cloud = switch($Environment) {
      "smc" {"EHNSW.SelfManagedCloud.01"}
      "cdh" {"CDHR-Child Digital Health Record"}
      }

    az account set -s $cloud
}
