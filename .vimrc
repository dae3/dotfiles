 " remember the vc version is at ~/dotfiles/.vimrc

" plugin load
set nocompatible
filetype off

call plug#begin('~/.vim/plugged')

Plug 'pangloss/vim-javascript'
Plug 'pprovost/vim-ps1'
Plug 'rafi/awesome-vim-colorschemes'
Plug 'freitass/todo.txt-vim'
Plug 'godlygeek/tabular'
Plug 'plasticboy/vim-markdown'
Plug 'vim-airline/vim-airline'
Plug 'tpope/vim-surround'
Plug 'aklt/plantuml-syntax'
Plug 'elzr/vim-json'
Plug 'hashivim/vim-terraform'
Plug 'in3d/vim-raml'
Plug 'sheerun/vim-polyglot'
Plug 'thaerkh/vim-indentguides'
Plug 'tpope/vim-fugitive'
Plug 'autozimu/LanguageClient-neovim', {
    \ 'branch': 'next',
    \ 'do': 'powershell -executionpolicy bypass -File install.ps1',
    \ }
Plug 'dense-analysis/ale'
Plug 'junegunn/fzf.vim'
Plug 'junegunn/fzf'
call plug#end()
filetype plugin indent on

" misc settings
set title
set hidden
set autochdir
set clipboard+=unnamed
set splitbelow
syntax on
color OceanicNext
nnoremap <silent> <F5> :w \| make <CR>
nnoremap <localleader>2 :ed $TODOTXT<CR>
nnoremap <localleader>2t :tabedit $TODOTXT<CR>
set tabstop=4
set shiftwidth=2
set softtabstop=2
set expandtab
set ignorecase
set encoding=utf-8
set number
set relativenumber
nnoremap <silent> <localleader>n :set relativenumber!<cr>
let mapleader="\\"
let maplocalleader="\\"
inoremap <esc> <nop>
nnoremap - ddp
nnoremap _ dd2kp
nnoremap <leader>ev :ed ~/.vimrc<cr>
nnoremap <leader>evt :tabedit ~/.vimrc<cr>
nnoremap <leader>sv :source ~/.vimrc<cr>
inoremap <C-s> <esc>:w<CR>
inoremap <C-s><C-s> <esc>:w<CR>i
nnoremap <C-s> :w<CR>
inoremap jk <esc>
set foldlevel=99
set spellsuggest=fast
set shortmess+=c
set belloff+=ctrlg
let g:python3_host_prog='c:/Python37/python.exe'

" autokparens
inoremap { {}<left>
inoremap [ []<left>
inoremap " ""<left>
inoremap ' ''<left>
inoremap ` ``<left>

" completion
set completeopt=preview,menuone,noinsert
set dictionary=expand('~/Documents/20k.txt')
let g:LanguageClient_serverCommands = {
    \ 'javascript': ['node','c:\users\daniel.everett\Documents\tools\javascript-typescript-langserver\lib\language-server-stdio.js'],
    \ 'terraform': [ 'c:\users\daniel.everett\Documents\tools\terraform-lsp.exe' ],
    \ }
nnoremap <silent> K :call LanguageClient#textDocument_hover()<CR>
nnoremap <silent> gd :call LanguageClient#textDocument_definition()<CR>
nnoremap <silent> <F2> :call LanguageClient#textDocument_rename()<CR>

" linting
let g:ale_linters = { 'javascript': [ 'c:\users\daniel.everett\Documents\tools\javascript-typescript-langserver\node_modules\.bin\tslint.cmd'] }

"netrw
let g:netrw_cygwin=0
let g:netrw_list_cmd="plink HOSTNAME ls -FLa "
let g:netrw_scp_cmd="pscp -q "
let g:netrw_rm_cmd="plink USEPORT HOSTNAME rm "
let g:netrw_rm_cmd="plink USEPORT HOSTNAME rm -f "
let g:netrw_winsize=20
let g:netrw_liststyle=3
nnoremap <silent> <c-n> :Lexplore<cr>
augroup netrw
    autocmd!
    autocmd filetype netrw nnoremap <silent> <buffer> <c-n> :bd!<cr>
augroup end

" font stuff
let g:gfsizebig=14
let g:gfsizesmall=12
let g:gfsize=g:gfsizebig
let g:gfname='Consolas'
function! Font_size_toggle()
    if g:gfsize == g:gfsizebig
	let g:gfsize = g:gfsizesmall
    else
	let g:gfsize = g:gfsizebig
    endif

    let &guifont=g:gfname . ':h' . g:gfsize
endfunction

" fugitive
nnoremap <C-g>a :Gwrite<CR>
nnoremap <C-g>c :Gcommit<CR>

" json
au! BufRead,BufNewFile *.json set filetype=json

augroup json_autocmd
    autocmd!
    autocmd FileType json set autoindent
    autocmd FileType json set formatoptions=tcq2l
    autocmd FileType json set textwidth=78 shiftwidth=2
    autocmd FileType json set foldmethod=syntax
augroup END

" todo
function! GetTodoContext(lnum)
    let l:cur_task = getline(a:lnum)
    let l:at_at = match(l:cur_task, "@")
    let l:spc_at = match(l:cur_task, " ", l:at_at + 1)
    return strpart(l:cur_task, l:at_at+1, l:spc_at-l:at_at)
endfunction

function! GotoTodoContext(lnum, reverse)
    let l:regex = '^\(@' . GetTodoContext(a:lnum) . '\)\@!'
    let l:sflags = 'w'
    if a:reverse
	let l:sflags = 'wb'
    endif

    call search(l:regex, l:sflags)
endfunction

command!  -nargs=? NotesGrep cd ~/notes | Rg <args>
command! NotesTodo NotesGrep \[ \]

" Powershell profile source control
augroup psprofile
    autocmd!
    autocmd BufWritePost ~/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1 write! ~/Documents/dotfiles/Microsoft.PowerShell_profile.ps1
augroup end

" simple Terraform workflow
augroup terraform
    autocmd!
    autocmd FileType terraform setlocal makeprg=terraform\ validate\ -no-color
    "autocmd FileType terraform autocmd BufWritePost <buffer> :lmake
    autocmd FileType terraform setlocal errorformat="Error\ loading\ files\ Error\ parsing %f:\ At\ %l:%c:\ %m"
augroup END

augroup todo
    autocmd!
    autocmd FileType todo setlocal autoread
    " autocmd FileType todo setlocal spell spelllang=en_au
    " autocmd FileType todo AutoSaveToggle
    autocmd FileType todo nnoremap <buffer> <localleader>U :%s/^([A-E]) //<CR>
    autocmd FileType todo nnoremap <buffer> <localleader>R :g/[IS]R[[:digit:]]\{6}/p<CR>

    autocmd FileType todo nnoremap <buffer> ]] :call GotoTodoContext(line('.'), 0)<cr>
    autocmd FileType todo nnoremap <buffer> [[ :call GotoTodoContext(line('.'), 1)<cr>
    autocmd FileType todo autocmd InsertLeave <buffer> :w
    autocmd FileType todo autocmd BufReadPost <buffer> :call TodoPriorityClearPrompted()
augroup END

nnoremap <leader>F :call Font_size_toggle()<CR>

" vim-javascript config
augroup javascript_folding
    au!
    au FileType javascript setlocal foldmethod=syntax
    au FileType javascript nnoremap <leader>/ 0i//<esc>
    au FileType javascript nnoremap <leader>// 02x<esc>
augroup END
let g:javascript_conceal_function             = "ƒ"

" vimrc auto reload & don't forget to commit
augroup vimrc
    au!
    " au BufWritePost .vimrc source % | write! ~/dotfiles/.vimrc | tabedit ~/dotfiles/.vimrc | call fugitive#Init() | Gstatus
    au BufWritePost .vimrc source % | write! ~/Documents/dotfiles/.vimrc
augroup END

function! VimrcVC()
    let l:vcvimrc = '~/dotfiles/Documents/.vimrc'

    let l:vcvimrcbuf = bufnr(expand(l:vcvimrc))
    if l:vcvimrcbuf > 0
	execute "bdelete " . l:vcvimrcbuf . " | write! " l:vcvimrc . " | edit " . l:vcvimrc . " | Gstatus"
    else
	execute "write! " . l:vcvimrc . " | edit " . l:vcvimrc . " | Gstatus"
    endif
endfunction

" abbreviations
" todo
iabbrev wtg @Waiting
iabbrev atolw @Online-Work

" markdown
let g:vim_markdown_autowrite = 1
" insert filename as level 1 title
function! InsertMarkdownTitle()
    let l:firstline = getline(1)
    let l:title = '# ' . expand('%:t:r')
    if match(l:firstline, l:title) == -1
	call append(0, l:title)
    endif
endfunction

"" auto bullet and wrap don't play well
"" https://github.com/plasticboy/vim-markdown/issues/232
let g:vim_markdown_auto_insert_bullets = 0
let g_vim_markdown_new_list_item_indent = 0
augroup markdown
    au!
    au FileType markdown setlocal conceallevel=2 spell spelllang=en_au
    au FileType markdown setlocal textwidth=0 wrap linebreak nolist
    " au FileType markdown AutoSaveToggle
    au FileType markdown setlocal comments=fb:>,fb:*,fb:+,fb:-
    au FileType markdown setlocal formatoptions -=q
    au FileType markdown setlocal formatlistpat=^\\s*\\d\\+\\.\\s\\+\\\|^\\s*\[-*+]\\s\\+
    autocmd FileType markdown autocmd InsertLeave <buffer> :w
    autocmd FileType markdown autocmd BufWritePre <buffer> call InsertMarkdownTitle()
augroup END
" let g:instant_markdown_slow = 1

" airline
let g:airline_theme='oceanicnextlight'

" tab labels
function! TabLabels()
    let label = v:lnum . ' '
    let aidx = v:lnum - 1

    if exists(g:tablab[0] && len(g:tablab) == 0)
	echo 'YAY'
	let label .= g:tablab[aidx]
    else
	let bl = tabpagebuflist(v:lnum)
	let label .= bufname(bl[tabpagewinnr(v:lnum) - 1])
    endif

    return label
endfunction

" set guitablabel=%{TabLabels()}
command! -bang -nargs=* Find call fzf#vim#grep('rg --column --line-number --no-heading --fixed-strings --ignore-case --no-ignore --hidden --follow --glob "!.git/*" --color "always" '.shellescape(<q-args>), 1, <bang>0)
" nnoremap <C-f> Find


" turn off search highlight with <CR>
nnoremap <silent> <CR> :nohlsearch<CR><CR>

" quick Google search
command! GLucky :call netrw#BrowseX("https://google.com/search?q=" . expand('<cword>'), "0")
nnoremap <silent> B :GLucky<cr>

" diff
set diffopt+=,vertical

" diff buffer with saved file
function! s:DiffWithSaved()
    let filetype=&ft
    diffthis
    vnew | r # | normal! 1Gdd
    diffthis
    exe "setlocal bt=nofile bh=wipe nobl noswf ro ft=" . filetype
endfunction
command! DiffSaved call s:DiffWithSaved()

" insert date in useful format for markdown headings
function! InsertDate()
    let l:date = strftime("%Y%m%d", localtime())
    execute 'normal! A' . l:date
endfunction

inoremap <localleader>mdd <ESC>:call InsertDate()<CR>

" selective cursorline
augroup cln
    autocmd!
    autocmd WinEnter * set cursorline
    autocmd WinLeave * set nocursorline
augroup end

" airline cleanup
let g:airline_section_z=""
let g:airline_theme="dark"

" Jira jump
function! JiraJump()
    let l:ticket =  'https://integratedcareportfolio.atlassian.net/browse/NCC-' . expand('<cword>')
    call openbrowser#open(l:ticket)
endfunction


" JSON outliner
function! JsonOutline(srcbuf)
    let l:lines = getbufline(a:srcbuf,1,'$')
    let l:data = []
    let l:lnum = 0
    let l:outlnum = 1
    let l:indent = 0

    " create or find and prepare our scratch buffer
    if exists("g:jsonoutlinemap")
	if exists("g:jsonoutlinemap[a:srcbuf]")
	    let l:scrbuf = g:jsonoutlinemap[a:srcbuf]
	else
	    let l:scrbuf = CreateJsonOutlineScratch(a:srcbuf)
	    let g:jsonoutlinemap[a:srcbuf] = l:scrbuf
	endif
    else
	let l:scrbuf = CreateJsonOutlineScratch(a:srcbuf)
	let g:jsonoutlinemap = {}
	let g:jsonoutlinemap[a:srcbuf] = l:scrbuf
    endif
    let l:scrwin = bufwinnr(l:scrbuf)
    execute l:scrwin . 'wincmd w | set ma | let b:srcbuf =' . a:srcbuf . ' | normal! ggdG'

    " process the parent buffer
    while l:lnum < len(l:lines)
	" only add lines containing a key to the list
	let l:match = matchlist(l:lines[l:lnum], '^\s*"\(\w\+\)"')
	if l:match != []
	    let l:data = add(l:data, { 'key' : l:match[1], 'iskey' : 1, 'lnum' : l:lnum+1, 'indent' : l:indent })
	    call append(l:outlnum, FormatOneLine(l:data[l:lnum]))
	    let l:outlnum += 1
	else
	    let l:data = add(l:data, { 'key' : '', 'iskey' : 0, 'lnum' : l:lnum+1,  'indent' : l:indent })
	endif

	" increase indent on { or [, decrease on } or ]
	" this will fail in non-simple cases like escaped brackets
	if l:lines[l:lnum] =~ '{\|['
	    let l:indent += 1
	elseif l:lines[l:lnum] =~  '}\|]'
	    let l:indent -= 1
	endif

	let l:lnum += 1
    endwhile

    setl nomodifiable
    nnoremap <silent> <buffer> <cr> :call JPJump()<cr>
endfunction

command! JsonOutline call JsonOutline(bufnr('%'))

function! JPJump()
    let l:line = getline('.')
    let l:data = matchlist(l:line, '^\s*\(\d\+\) \.* \(\w\+\)')
    execute bufwinnr(b:srcbuf) . 'wincmd w'
    execute 'normal! ' . l:data[1] . 'G'
endfunction

function! FormatOneLine(line)
    call assert_true(type(a:line) == v:t_dict)
    if a:line['iskey'] == 1
	let l:ret = printf("%5d %s %s", a:line['lnum'], repeat('.', a:line['indent']), a:line['key'])
    else
	let l:ret = ""
    endif
    return l:ret
endfunction

function! CreateJsonOutlineScratch(srcbuf)
    40 vsplit __JSON Outline__
    noswapfile hide enew
    setlocal buftype=nofile
    setlocal bufhidden=hide
    setlocal nospell noswapfile nonumber norelativenumber
    let b:scrbuf = a:srcbuf
    autocmd! BufUnload <buffer> call DeleteJsonOutlineScratch()
    return bufnr('%')
endfunction

function! DeleteJsonOutlineScratch()
    " Delete this buffer from g:jsonoutlinemap

    " Finds the parent buffer from the buffer-local variable of the autocommand's
    " target buffer. NB: expand('<abuf>') returns String but getbufvar requires
    " a Number
    let l:outlinebuf = str2nr(expand('<abuf>'))
    let l:srcbuf = getbufvar(l:outlinebuf, 'srcbuf')
    unlet g:jsonoutlinemap[l:srcbuf]

    " clean up the autocommand
    execute "au! BufUnload <buffer=" . l:outlinebuf . ">"
endfunction

function! TodoPriorityClearPrompted()
    " Prompt to clear priorities upon opening todo.txt
    " if it was last modified more than 12 hours ago
    "
    if localtime() - getftime(expand('%')) > 43200
	if input('Reset priorities? ', 'y') == 'y'
	    normal :%s/^([A-E]) //<cr>
	endif
    endif
endfunction

command! VimgrepUnderCursor vimgrep <cword> % | copen
