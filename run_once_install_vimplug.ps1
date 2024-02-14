{{- if eq .chezmoi.os "windows" }}

Write-Output "Looks like a new vim install, downloading vim-plug..."
Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim -OutFile $env:USERPROFILE\vimfiles\autoload\plug.vim

{{- end }}
