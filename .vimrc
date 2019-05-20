set nocompatible
filetype off

set rtp+=~/.vim/bundle/Vundle.vim
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

call vundle#end()
filetype plugin indent on

nnoremap <localleader>2 :ed ~/dropbox/todo.txt/todo.txt<CR>

syntax on
color OceanicNext
if has('gui_running')
	set guifont=Inconsolata
endif
set guioptions-=T
set ts=2
set sw=2
se ic
set encoding=utf-8
set number

inoremap <C-s> <esc>:w<CR>
nnoremap <C-s> :w<CR>

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

" syntastic
set statusline+=%#waningmsg#
set statusline+=%{SyntasticStatuslineFlag()}
set statusline+=%*

map <C-n> :NERDTreeToggle<CR>

let g:syntastic_always_populate_loc_list = 1
let g:syntastic_auto_loc_list = 1
let g:syntastic_check_on_open = 1
let g:syntastic_check_on_wq = 0
let g:syntastic_javascript_checkers = ['eslint' ]
