set nocompatible
filetype off

call plug#begin('~/.vim/plugged')

Plug 'pangloss/vim-javascript'
Plug 'pprovost/vim-ps1'
Plug 'mxw/vim-jsx'
Plug 'rafi/awesome-vim-colorschemes'
Plug 'scrooloose/nerdtree'
Plug 'freitass/todo.txt-vim'
Plug 'leafgarland/typescript-vim'
Plug 'godlygeek/tabular'
Plug 'plasticboy/vim-markdown'
Plug 'ctrlpvim/ctrlp.vim'
Plug 'majutsushi/tagbar'
Plug 'tpope/vim-fugitive'
Plug 'vim-airline/vim-airline'
Plug 'tpope/vim-surround'
Plug 'digitaltoad/vim-jade'
Plug 'junegunn/fzf'
Plug 'junegunn/fzf.vim'
" Plugin 'suan/vim-instant-markdown'
Plug 'neoclide/coc.nvim', {'branch': 'release'}
Plug 'tyru/open-browser.vim'
Plug 'previm/previm'
"Plug 'dtjm/plantuml-syntax.vim'
Plug 'aklt/plantuml-syntax'
Plug 'jeetsukumaran/vim-buffergator'
Plug 'elzr/vim-json'
Plug 'hashivim/vim-terraform'
Plug 'in3d/vim-raml'
Plug 'xavierchow/vim-swagger-preview'
Plug 'martinda/jenkinsfile-vim-syntax'
Plug 'modille/groovy.vim'
Plug 'mogelbrod/vim-jsonpath'
Plug 'psliwka/vim-smoothie'

call plug#end()
filetype plugin indent on

set autochdir

" clipboard
set clipboard+=unnamed

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
 autocmd FileType json set softtabstop=2 tabstop=8
 autocmd FileType json set expandtab
 autocmd FileType json set foldmethod=syntax
augroup END
							 
" ctrlp
let g:ctrlp_working_path_mode = 'rac'
let g:ctrlp_switch_buffer = 'E'
let g:ctrlp_brief_prompt = 1
let g:ctrlp_custom_ignore = 'node_modules'

" buffergator
let g:buffergator_suppress_keymaps = 1
nnoremap <C-b> :BuffergatorOpen<CR>

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

nnoremap <localleader>2 :ed $TODOTXT<CR>
nnoremap <localleader>2t :tabedit $TODOTXT<CR>

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
augroup END

syntax on
" color solarized8_high
color OceanicNext

" font stuff
let g:gfsizebig=14
let g:gfsizesmall=10
let g:gfsize=g:gfsizebig
function! Font_size_toggle()
	if g:gfsize == g:gfsizebig
		let g:gfsize = g:gfsizesmall
	else
		let g:gfsize = g:gfsizebig
	endif

	let &guifont='Consolas:h'.g:gfsize
endfunction

nnoremap <leader>F :call Font_size_toggle()<CR>

if has('gui_running')
	set guioptions-=T
	set guioptions-=m
	set guioptions-=l
	set guioptions-=L
	set guioptions-=r
	if has('win32')
		set guifont="Consolas:h" . g:gfsize
	else
		set guifont=Inconsolata
	endif
else
  " blows up for some reason when running in console
  let g:airline#extensions#tagbar#enabled = 0
endif


set ts=2
set sw=2
se ic
set encoding=utf-8
set number
set relativenumber
nnoremap <silent> <localleader>n :set relativenumber!<cr>

" misc
inoremap <C-s> <esc>:w<CR>
inoremap <C-s><C-s> <esc>:w<CR>i
nnoremap <C-s> :w<CR>
inoremap jk <esc>
set spellsuggest=fast

" folding
set foldlevel=99
nnoremap <leader><space> za

" vim-javascript config
augroup javascript_folding
	au!
	au FileType javascript setlocal foldmethod=syntax
	au FileType javascript nnoremap <leader>/ 0i//<esc>
	au FileType javascript nnoremap <leader>// 02x<esc>
        au FileType javascript setlocal tabstop=4
augroup END
let g:javascript_conceal_function             = "ƒ"

let mapleader="\\"
let maplocalleader="\\"

" line move
nnoremap - ddp
nnoremap _ dd2kp


" vimrc quick change
nnoremap <leader>ev :vsplit ~/.vimrc<cr>
nnoremap <leader>evt :tabedit ~/.vimrc<cr>
nnoremap <leader>sv :source ~/.vimrc<cr>
augroup vimrc
	au!
	" au FileType vim au <buffer> BufWritePost :source ~/_vimrc<cr>
	"au BufWritePost _vimrc :source ~/_vimrc<cr>
	au BufWritePost .vimrc silent write! ~/dotfiles/.vimrc
	au BufWritePost .vimrc echo "Don't forget to commit"
	augroup END

" for MUcomplete
set completeopt+=menuone
set completeopt+=noselect
set shortmess+=c
set belloff+=ctrlg
let g:mucomplete#enable_auto_at_startup=1

" tagbar etc
nnoremap <F8> :TagbarOpenAutoClose<CR>

" NERDTree
map <C-n> :NERDTreeFocus<CR>
let NERDTreeMinimalMenu=1

" abbreviations
" todo
iabbrev wtg @Waiting
iabbrev atolw @Online-Work
" PRINCE2 study notes
iabbrev p2 PRINCE2
iabbrev PM Project Manager
iabbrev mgmt management

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

" coc.vim 
" " adapted from https://github.com/neoclide/coc.nvim#example-vim-configuration
" " if hidden is not set, TextEdit might fail.
set hidden

autocmd FileType terraform let b:coc_root_patterns = ['.terraform' ]

" Some servers have issues with backup files, see #649
set nobackup
set nowritebackup

" Better display for messages
set cmdheight=2

" You will have bad experience for diagnostic messages when it's default 4000.
set updatetime=300

" don't give |ins-completion-menu| messages.
set shortmess+=c

" always show signcolumns
set signcolumn=yes

" Use tab for trigger completion with characters ahead and navigate.
" Use command ':verbose imap <tab>' to make sure tab is not mapped by other plugin.
inoremap <silent><expr> <TAB>
      \ pumvisible() ? "\<C-n>" :
      \ <SID>check_back_space() ? "\<TAB>" :
      \ coc#refresh()
inoremap <expr><S-TAB> pumvisible() ? "\<C-p>" : "\<C-h>"

function! s:check_back_space() abort
  let col = col('.') - 1
  return !col || getline('.')[col - 1]  =~# '\s'
endfunction

" Use <c-space> to trigger completion.
inoremap <silent><expr> <c-space> coc#refresh()

" Use <cr> to confirm completion, `<C-g>u` means break undo chain at current position.
" Coc only does snippet and additional edit on confirm.
inoremap <expr> <cr> pumvisible() ? "\<C-y>" : "\<C-g>u\<CR>"

" Use `[c` and `]c` to navigate diagnostics
nmap <silent> [c <Plug>(coc-diagnostic-prev)
nmap <silent> ]c <Plug>(coc-diagnostic-next)

" Remap keys for gotos
nmap <silent> gd <Plug>(coc-definition)
nmap <silent> gy <Plug>(coc-type-definition)
nmap <silent> gi <Plug>(coc-implementation)
nmap <silent> gr <Plug>(coc-references)

" Use K to show documentation in preview window
nnoremap <silent> K :call <SID>show_documentation()<CR>

function! s:show_documentation()
  if (index(['vim','help'], &filetype) >= 0)
    execute 'h '.expand('<cword>')
  else
    call CocAction('doHover')
  endif
endfunction

" Highlight symbol under cursor on CursorHold
autocmd CursorHold * silent call CocActionAsync('highlight')

" Remap for rename current word
nmap <leader>rn <Plug>(coc-rename)

" Remap for format selected region
xmap <leader>f  <Plug>(coc-format-selected)
nmap <leader>f  <Plug>(coc-format-selected)

augroup mygroup
  autocmd!
  " Setup formatexpr specified filetype(s).
  autocmd FileType typescript,json setl formatexpr=CocAction('formatSelected')
  " Update signature help on jump placeholder
  autocmd User CocJumpPlaceholder call CocActionAsync('showSignatureHelp')
augroup end

" Remap for do codeAction of selected region, ex: `<leader>aap` for current paragraph
xmap <leader>a  <Plug>(coc-codeaction-selected)
nmap <leader>a  <Plug>(coc-codeaction-selected)

" Remap for do codeAction of current line
nmap <leader>ac  <Plug>(coc-codeaction)
" Fix autofix problem of current line
nmap <leader>qf  <Plug>(coc-fix-current)

" Use <tab> for select selections ranges, needs server support, like: coc-tsserver, coc-python
nmap <silent> <TAB> <Plug>(coc-range-select)
xmap <silent> <TAB> <Plug>(coc-range-select)
xmap <silent> <S-TAB> <Plug>(coc-range-select-backword)

" Use `:Format` to format current buffer
command! -nargs=0 Format :call CocAction('format')

" Use `:Fold` to fold current buffer
command! -nargs=? Fold :call     CocAction('fold', <f-args>)

" use `:OR` for organize import of current buffer
command! -nargs=0 OR   :call     CocAction('runCommand', 'editor.action.organizeImport')

" Using CocList
" Show all diagnostics
nnoremap <silent> <space>a  :<C-u>CocList diagnostics<cr>
" Manage extensions
nnoremap <silent> <space>e  :<C-u>CocList extensions<cr>
" Show commands
nnoremap <silent> <space>c  :<C-u>CocList commands<cr>
" Find symbol of current document
nnoremap <silent> <space>o  :<C-u>CocList outline<cr>
" Search workspace symbols
nnoremap <silent> <space>s  :<C-u>CocList -I symbols<cr>
" Do default action for next item.
nnoremap <silent> <space>j  :<C-u>CocNext<CR>
" Do default action for previous item.
nnoremap <silent> <space>k  :<C-u>CocPrev<CR>
" Resume latest coc list
nnoremap <silent> <space>p  :<C-u>CocListResume<CR>

" coc - airline
let g:airline#extensions#coc#enabled =  1

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

" open-browser
" nnoremap <silent> B :OpenBrowserSmartSearch expand(<cword>)<cr>
nmap <silent> B <Plug>(openbrowser-smart-search)
vmap <localleader>B <Plug>(openbrowser-smart-search)

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

" neovim specific
if has('nvim')
       au VimEnter * GuiPopupmenu 0
       au VimEnter * GuiTabline 0
endif

" insert date in useful format for markdown headings
function! InsertDate()
  let l:date = strftime("%Y%m%d", localtime())
  execute 'normal! A' . l:date
endfunction

inoremap <localleader>mdd <ESC>:call InsertDate()<CR>
