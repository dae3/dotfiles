set nocompatible
filetype off

if has('win32')
	set rtp+=~/vimfiles/bundle/Vundle.vim
else
	set rtp+=~/.vim/bundle/Vundle.vim
endif
call vundle#begin()

Plugin 'VundleVim/Vundle.vim'
" Plugin 'jnurmine/Zenburn'
Plugin 'pangloss/vim-javascript'
Plugin 'mxw/vim-jsx'
Plugin 'lifepillar/vim-mucomplete'
Plugin 'rafi/awesome-vim-colorschemes'
" Plugin 'ludovicchabant/vim-gutentags'
Plugin 'vim-syntastic/syntastic'
Plugin 'scrooloose/nerdtree'
Plugin 'freitass/todo.txt-vim'
Plugin 'leafgarland/typescript-vim'
Plugin 'godlygeek/tabular'
Plugin 'plasticboy/vim-markdown'
Plugin 'ctrlpvim/ctrlp.vim'
Plugin 'majutsushi/tagbar'
Plugin 'vim-scripts/vim-auto-save'

call vundle#end()
filetype plugin indent on

nnoremap <localleader>2 :ed $TODOTXT<CR>
augroup todo
	autocmd!
	autocmd FileType todo setlocal autoread spell spelllang=en_au
augroup END
nnoremap <localleader>U :%s/^([A-E]) //<CR>
nnoremap <localleader>R :g/[IS]R[[:digit:]]\{6}/p<CR>

syntax on
color OceanicNext

if has('gui_running')
	set guioptions-=T
	set guioptions-=m
	set guioptions-=l
	set guioptions-=L
	set guioptions-=r
	if has('win32')
		set guifont=Consolas:h11
	else
		set guifont=Inconsolata
	endif
endif

set guioptions-=T
set ts=2
set sw=2
se ic
set encoding=utf-8
set number

" misc
inoremap <C-s> <esc>:w<CR>i
nnoremap <C-s> :w<CR>
inoremap jk <esc>

" folding
set foldlevel=99
nnoremap <leader><space> za

" vim-javascript config
augroup javascript_folding
    au!
    au FileType javascript setlocal foldmethod=syntax
augroup END
let g:javascript_conceal_function             = "ƒ"

let mapleader="\\"
let maplocalleader="\\"

" line move
nnoremap - ddp
nnoremap _ dd2kp


" vimrc quick change
nnoremap <leader>ev :vsplit $MYVIMRC<cr>
nnoremap <leader>sv :source $MYVIMRC<cr>

" js comment
nnoremap <leader>/ 0i//<esc>
nnoremap <leader>// 02x<esc>

" for MUcomplete
set completeopt+=menuone
set completeopt+=noselect
set shortmess+=c
set belloff+=ctrlg
let g:mucomplete#enable_auto_at_startup=1

" tagbar etc
nnoremap <F8> :TagbarOpenAutoClose<CR>

" syntastic
set statusline+=%#waningmsg#
set statusline+=%{SyntasticStatuslineFlag()}
set statusline+=%*

" NERDTree
map <C-n> :NERDTreeToggle<CR>
let NERDTreeMinimalMenu=1

let g:syntastic_always_populate_loc_list = 1
let g:syntastic_auto_loc_list = 1
let g:syntastic_check_on_open = 1
let g:syntastic_check_on_wq = 0
let g:syntastic_javascript_checkers = ['eslint' ]

" abbreviations
" todo
iabbrev atolw @Online-Work
iabbrev gbr Greensborough
iabbrev p2 PRINCE2

" markdown
let g:vim_markdown_json_frontmatter=1
let g:vim_markdown_autowrite = 1
augroup markdown
	au!
	au FileType markdown setlocal conceallevel=2 spell spelllang=en_au
	au FileType markdown setlocal mousemodel=popup textwidth=50
	au FileType markdown setlocal textwidth=80 wrap linebreak nolist
	au FileType markdown AutoSaveToggle
augroup END
