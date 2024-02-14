{{- if eq .chezmoi.os "linux" }}
#!/bin/sh
echo "Looks like a new vim install, downloading vim-plug..."
curl -sfLo ~/.vim/autoload/plug.vim --create-dirs https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
if [ $? -eq 0 ]; then
  echo "Done"
else
  echo "Failed"
fi
{{- end }}
