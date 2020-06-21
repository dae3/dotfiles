setlocal foldmethod=syntax

let b:ale_linters = [ 'clangd' ]

" autoformat on save 
augroup go
  au!
  au BufWritePre <buffer> :call LanguageClient#textDocument_formatting()
augroup end

setl omnifunc=ale#completion#OmniFunc
