setlocal autoread
nnoremap <buffer> <localleader>U :%s/^([A-E]) //<CR>
nnoremap <buffer> <localleader>R :g/[IS]R[[:digit:]]\{6}/p<CR>

function! s:GetTodoContext(lnum)
  let l:cur_task = getline(a:lnum)
  let l:at_at = match(l:cur_task, "@")
  let l:spc_at = match(l:cur_task, " ", l:at_at + 1)
  return strpart(l:cur_task, l:at_at+1, l:spc_at-l:at_at)
endfunction

function! <SID>GotoTodoContext(lnum, reverse)
  let l:regex = '^\(@' . s:GetTodoContext(a:lnum) . '\)\@!'
  let l:sflags = 'w'
  if a:reverse
    let l:sflags = 'wb'
  endif

  call search(l:regex, l:sflags)
endfunction

nnoremap <silent> <buffer> ]] :call <SID>GotoTodoContext(line('.'), 0)<cr>
nnoremap <silent> <buffer> [[ :call <SID>GotoTodoContext(line('.'), 1)<cr>

augroup todo
  au!
  autocmd InsertLeave <buffer> :w
  autocmd BufReadPost <buffer> :call <SID>TodoPriorityClearPrompted()
augroup END

" Completion
inoremap <expr> <buffer> @ <SID>TodoAt()
setl dictionary=expand('~/Documents/20k.txt')

function! <SID>TodoAt()
  if col('.') == 1 
    return "@\<C-X>\<C-U>"
  else
    return '@'
  endif
endfunction

function! s:TodoContextMatch(base, _, ctx)
  if match(a:ctx, a:base) == -1
    return ''
  else
    return a:ctx
  endif
endfunction

function! s:TodoGetContext(_, line)
  let l:at = stridx(a:line, '@')
  if l:at >= 0
    let l:atend = stridx(a:line, ' ', l:at + 1)
    return strcharpart(a:line, l:at, l:atend - l:at)
  else
    return ''
  endif
endfunction

function! s:TodoGetAllContexts()
  let l:lines = getline('.','$')
  return uniq(sort(map(l:lines, function('s:TodoGetContext'))))
endfunction

function! TodoCompleteFunc(findstart, base)
  if a:findstart == 1
    let l:matchcol = match(getline('.'), '@')
    if l:matchcol == -1
      return -3
    else
      return l:matchcol
    endif
  else
    let l:MapFunc = function('s:TodoContextMatch', [a:base])
    let l:contexts = s:TodoGetAllContexts()
    return map(l:contexts, l:MapFunc)
  endif
endfunction

inoremap <buffer> <Tab> <C-x><C-u>

setlocal completefunc=TodoCompleteFunc
