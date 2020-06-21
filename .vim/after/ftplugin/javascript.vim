setlocal foldmethod=syntax

let b:ale_linters = [ 'tsserver',' eslint' ]
let b:ale_fixers = [ 'eslint' ]

let g:javascript_conceal_function             = "ƒ"

nnoremap <leader>/ 0i//<esc>
nnoremap <leader>// 02x<esc>

inoreabbrev <buffer> rq require(''
