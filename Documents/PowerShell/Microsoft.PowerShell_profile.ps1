function Stop-NamedProcess {
  Param(
      [parameter(Mandatory=$true)]
      [String] $processName
  )
    Get-Process | Where-Object Name -Like "*$processName*" | Stop-Process -Force
}

function Get-MyIPAddress {
    (Invoke-WebRequest https://api.ipify.org?format=json | convertfrom-json).ip
}

function Set-AzureAccount {
    Param([parameter(Mandatory=$true)] [ValidateSet("demo","smc","cdh","acloud","ukcloud","mslab","slhd","adev")][String] $Environment)

    $cloud = switch($Environment) {
      "acloud" { "409f010a-619c-48fc-b1b9-0832208bb0d0" }
      "ukcloud" { "402cbda8-4a37-4a55-82cb-200b7236d454" }
      "mslab" { "6307f5da-5fc1-48e4-a908-192df2dbfce4" }
      "adev" { "5937f7e0-fc9d-41f0-9c97-1210cd48ac81" }
      "demo" { "87773a7b-5957-4db8-a1df-2c37cc60eb09" }
      }

    az account set -s $cloud
}
function ConvertFrom-Base64String ([String] $encoded) {
  return [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($encoded))
}

function ConvertTo-Base64String ([String] $s) {
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($s))
  }

function Set-WindowTitle ([string] $title) { $Host.UI.RawUI.WindowTitle = $title }

function Connect-AlcCloud {
    Param(
            [parameter(Mandatory = $true)] [ValidateSet("anz","uk","demo","ukdemo")] [String] $cloud,
            [parameter()] [String] $pubkey = (Join-Path $ENV:USERPROFILE ".ssh/acloud.pub"),
            [parameter()] [String] $privkey = ($pubkey -Replace '.pub',''),
            [parameter()] [int] $port = 8444,
            [parameter(Mandatory = $true)] [String] $pat
         )

    $global:ProgressPreference = 'SilentlyContinue'

    # use `az pipelines list --organization https://dev.azure.com/alcidion --project 'Alcidion Cloud'` to get
    # pipeline IDs
    $pipelineid = switch($cloud) {
        "anz" { "249" }
        "uk" { "225" }
        "demo" { "297" }
        "ukdemo" { "313" }
    }

    $apiserver = switch($cloud) {
        "anz" { 'alc-cloud-d5ac7984.7cce2c5e-d5eb-4ac9-97bf-808e04532623.privatelink.australiaeast.azmk8s.io:443' }
        "uk" { 'alc-cloud-4fdc5260.f2615739-95df-457f-b90c-4d8cc52113dc.privatelink.uksouth.azmk8s.io:443' }
        "demo" { 'demo-cloud-e9285c0b.85325e84-d449-4883-9c87-8069a73a898b.privatelink.australiaeast.azmk8s.io:443' }
        "ukdemo" { 'uk-demo-b5nfhbqd.hcp.uksouth.azmk8s.io:443' }
    }

    $azdomain = switch($cloud) {
        "anz" {'australiaeast'}
        "uk" {'uksouth'}
        "demo" {'australiaeast'}
        "ukdemo" {'uksouth'}
    }

    $devopsproject = switch($cloud) {
        "anz" { "Alcidion%20Cloud" }
        "uk" { "Alcidion%20Cloud" }
        "demo" { "Research" }
        "ukdemo" { "Alcidion%20Cloud" }
        }

    $devopsuri = "https://dev.azure.com/alcidion/$devopsproject"

    $baseuri = switch($cloud) {
        "anz" { "$devopsuri/_apis/pipelines" }
        "uk" { "$devopsuri/_apis/pipelines" }
        "demo" { "$devopsuri/_apis/pipelines" }
        "ukdemo" { "$devopsuri/_apis/pipelines" }
    }

    $creds =New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ".", (ConvertTo-SecureString -String $pat -AsPlainText -Force)
    if ($cloud -eq "ukdemo") {
        $jumpbox = "$($ENV:USERNAME.Replace('.','-'))-uk-demo.$($azdomain).cloudapp.azure.com"
    } else {
        $jumpbox = "$($ENV:USERNAME.Replace('.','-')).$($azdomain).cloudapp.azure.com"
    }
    write-host "Testing connection to jumpbox $jumpbox..."

    # is there already a jumpbox running?
    if (resolve-dnsname -erroraction silentlycontinue -type a -name $jumpbox) {
        if (-not (test-netconnection $jumpbox -erroraction silentlycontinue -port 22 -InformationLevel Quiet)) {
            Write-Host -ForegroundColor Red "Jumphost name $jumpbox resolves, but no response on port 22 - is another jumpbox pipeline already running?"
        } else {
            Write-Host -ForegroundColor Green "Looks like you already have a jumphost"
            $jbready = $true
        }
    } else {
        Write-Host "No jumpbox found, starting a pipeline run"
        if ($cloud -eq "demo") {
            $branch = "refs/heads/users/geralds/demo-kube"
        } else {
            $branch = "main"
        }
        # https://stackoverflow.com/questions/55854660/why-doesnt-this-string-serialize-to-a-simple-json-string-in-powershell/55855052#55855052
        $body = @{previewRun = $false;resources = @{repositories=@{self=@{refName=$branch}};pipelines = @(@{version = '1'})};templateParameters = @{ssh_public_key = (cat $pubkey).psObject.BaseObject;source_ips = (Get-MyIPAddress)}}
        Invoke-RestMethod -Authentication Basic -Credential $creds -Method Post -ContentType 'application/json' `
            "$baseuri/$pipelineid/runs?api-version=7.1-preview.1" -Body (ConvertTo-Json -Depth 5 $body) | Set-Variable pipeline

            if ($pipeline.state -ne "inProgress") {
                Write-Host -ForegroundColor Red "Unexpected response from DevOps API: $pipeline"
            } else {

                # Clear old entry from ~/.ssh/known_hosts
                $known_hosts = "${ENV:USERPROFILE}/.ssh/known_hosts"
                (Get-Content $known_hosts | Select-String -NotMatch -Pattern "^$jumpbox") | Set-Content -Path $known_hosts

                # wait until the jumpbox responds
                Write-Host -ForegroundColor Yellow "Approve the pipeline stage at $($devopsuri)/_build/results?buildId=$($pipeline.id)&view=results, then hit any key"
                $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') > $null
                Write-Host "Waiting for jumpbox DNS name to resolve..."
                while (-not (resolve-dnsname -erroraction silentlycontinue -type a -name $jumpbox)) { sleep -seconds 30 }
                Write-Host "Waiting for jumpbox to respond on TCP/22..."
                while (-not (test-netconnection $jumpbox -port 22 -erroraction silentlycontinue -InformationLevel Quiet)) { sleep -seconds 10 }
                $jbready = $true
            }
    }

    if ($jbready) {
        Write-Host -ForegroundColor Green "Connecting to jumpbox and port-forwarding localhost:$($port) to $apiserver"
            ssh -i $privkey -L "$($port):$($apiserver)" "$($ENV:USERNAME.Replace('.','_'))@$($jumpbox)"

            Write-Host -ForegroundColor Yellow "Approve the pipeline stage at $($devopsuri)/_build/results?buildId=$($pipeline.id)&view=results to delete your jumpbox"
    }
}

function Get-MyIPAddress {
    (Invoke-WebRequest https://api.ipify.org?format=json | convertfrom-json).ip
}

function Delete-OrphanBranches([boolean] $prompt = $true) {
    $prefix = 'users/daniel'
    git branch -a --format='%(refname:lstrip=1)' | sls $prefix | set-variable branches
        $branches | sls -Pattern ^remotes | %{ ($_ -split '/')[4] } | Set-Variable remotebranches
        $branches | sls -Pattern ^heads | %{ ($_ -split '/')[3] } | Set-Variable localbranches

        $localbranches | Foreach-Object {
            if (-not ($remotebranches -contains $_)) {
                write-host $_
                    if ($prompt) { write-host "Delete $_ ?" }
                    if ((-not $prompt) -or ($Host.UI.RawUI.ReadKey().Character -eq 'y')) {
                        git branch -D "$prefix/$_"
                    }
            }
        }
}

function Get-AzureAccount() {
    az account list --all -o json | jq -r '.[] | select(.isDefault == true) | .id'
}

function Login-Acr([string] $name = 'precision') {
    Get-AzureAccount | Set-Variable currentAccount
    Set-AzureAccount adev
    helm repo remove $name
    az acr login -n $name --expose-token -o tsv --query accessToken | helm registry login "$($name).azurecr.io" --username '00000000-0000-0000-0000-000000000000' --password-stdin
    az acr helm repo add -n $name
    az account set -s $currentAccount
}

function New-ScratchDir() {
    Join-Path $ENV:USERPROFILE "Desktop" "scratch-$((New-Guid).Guid)" | Set-Variable scratch
    if (Test-Path $scratch) {
        Write-Host -ForegroundColor Red "Path $scratch already exists. Unlikely, but true. I give up."
    } else {
        $ENV:scratch = $scratch
        New-Item -Type Directory -Path $scratch
        Set-Location $scratch
    }
}

# https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-completion.html#cli-command-completion-windows
Register-ArgumentCompleter -Native -CommandName aws -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)
        $env:COMP_LINE=$wordToComplete
        if ($env:COMP_LINE.Length -lt $cursorPosition){
            $env:COMP_LINE=$env:COMP_LINE + " "
        }
        $env:COMP_POINT=$cursorPosition
        aws_completer.exe | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
        Remove-Item Env:\COMP_LINE
        Remove-Item Env:\COMP_POINT
}

kubectl completion powershell | out-string | invoke-expression
helm completion powershell | out-string | invoke-expression
Import-Module posh-git
Set-PSReadLineOption -EditMode Vi

function prompt {
    if ($NestedPromptLevel > 0) { Write-Host -ForegroundColor Blue -NoNewline $NestedPromptLevel }
    Write-Host -ForegroundColor cyan -NoNewline "$($ENV:USERNAME)@$($ENV:COMPUTERNAME) "
    Write-Host -ForegroundColor Yellow -NoNewline $((Get-Location).Path.Replace("$ENV:USERPROFILE","~"))
    Write-Host -ForegroundColor White -nonewline " PS>"
    return " "
}
