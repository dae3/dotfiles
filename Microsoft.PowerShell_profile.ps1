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
New-Alias -Name kc -Value kubectl

function Set-KubeContextNamespace([string] $namespace) { kubectl config set-context --current --namespace $namespace }
New-Alias -Name kcn -Value Set-KubeContextNamespace

Import-Module 'C:\tools\poshgit\dahlbyk-posh-git-9bda399\src\posh-git.psd1'

function Get-RandomPassword {(Invoke-WebRequest "https://www.random.org/passwords/?num=1&len=8&format=plain&rnd=new").content.Trim() }

function Start-Drone { aws ec2 start-instances --instance-ids $ENV:DRONE_INSTANCE_ID }
function Stop-Drone { aws ec2 stop-instances --instance-ids $ENV:DRONE_INSTANCE_ID }

function Get-TodayTasks { Get-Content $ENV:TODOTXT | Select-String -Pattern '^\([A-Z]\)' }

Set-PSReadLineOption -EditMode Emacs

function Set-AzureAccount {
    Param([parameter(Mandatory=$true)] [ValidateSet("smc","cdh")][String] $Environment)

    $cloud = switch($Environment) {
      "smc" {"EHNSW.SelfManagedCloud.01"}
      "cdh" {"CDHR-Child Digital Health Record"}
      }

    az account set -s $cloud
}


# xmouse
Add-Type -TypeDefinition @'
    using System;
    using System.Runtime.InteropServices;
    using System.ComponentModel;

    public static class Spi {
        [System.FlagsAttribute]
        private enum Flags : uint {
            None            = 0x0,
            UpdateIniFile   = 0x1,
            SendChange      = 0x2,
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SystemParametersInfo(
            uint uiAction, uint uiParam, UIntPtr pvParam, Flags flags );

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SystemParametersInfo(
            uint uiAction, uint uiParam, out bool pvParam, Flags flags );

        private static void check( bool ok ) {
            if( ! ok )
                throw new Win32Exception( Marshal.GetLastWin32Error() );
        }

        private static UIntPtr ToUIntPtr( this int value ) {
            return new UIntPtr( (uint) value );
        }

        private static UIntPtr ToUIntPtr( this bool value ) {
            return new UIntPtr( value ? 1u : 0u );
        }

        public static bool GetActiveWindowTracking() {
            bool enabled;
            check( SystemParametersInfo( 0x1000, 0, out enabled, Flags.None ) );
            return enabled;
        }

        public static void SetActiveWindowTracking( bool enabled ) {
            // note: pvParam contains the boolean (cast to void*), not a pointer to it!
            check( SystemParametersInfo( 0x1001, 0, enabled.ToUIntPtr(), Flags.SendChange ) );
        }
        public static bool GetActiveWindowRaising() {
            bool enabled;
            check( SystemParametersInfo( 0x100D, 0, out enabled, Flags.None ) );
            return enabled;
        }

        public static void SetActiveWindowRaising( bool enabled ) {
            // note: pvParam contains the boolean (cast to void*), not a pointer to it!
            check( SystemParametersInfo( 0x100D, 0, enabled.ToUIntPtr(), Flags.SendChange ) );
        }
        public static void SetActiveWindowTrackingTimeout( int millis ) {
            // note: pvParam contains the boolean (cast to void*), not a pointer to it!
            check( SystemParametersInfo( 0x2003, 0, millis.ToUIntPtr(), Flags.SendChange ) );
        }
    }
'@

function Set-XMouseBehaviour([bool] $tracking, [bool] $raising, [int] $delay) {
  [Spi]::SetActiveWindowTracking(  $tracking )
    [Spi]::SetActiveWindowRaising(  $raising )
      [Spi]::SetActiveWindowTrackingTimeout( $delay)
}

function ConvertFrom-Base64String ([String] $encoded) {
  return [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($encoded))
}

set-prompt
set-theme Agnoster
$DefaultUser = 'daniel.everett'
