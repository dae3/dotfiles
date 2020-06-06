setlocal autoread
nnoremap <buffer> <localleader>U :%s/^([A-E]) //<CR>
nnoremap <buffer> <localleader>R :g/[IS]R[[:digit:]]\{6}/p<CR>

" Navigate back or forward a context
function! <SID>GotoTodoContext(lnum, reverse)
  let l:cur_task = getline(a:lnum)
  let l:at_at = match(l:cur_task, "@")
  let l:spc_at = match(l:cur_task, " ", l:at_at + 1)
  
  " search for the next (previous) line *not* matching the current line's context
  call search('^\(@' . strpart(l:cur_task, l:at_at+1, l:spc_at-l:at_at) . '\)\@!', a:reverse ? 'wb' : 'w')
endfunction

nnoremap <silent> <buffer> ]] :call <SID>GotoTodoContext(line('.'), 0)<cr>
nnoremap <silent> <buffer> [[ :call <SID>GotoTodoContext(line('.'), 1)<cr>

augroup todo
  au!
  autocmd InsertLeave <buffer> :w
  autocmd BufReadPost <buffer> :call <SID>TodoPriorityClearPrompted()
augroup END

" Completion
inoremap <expr> <buffer> @ <SID>TodoCompeteTrigger('@', 1)
inoremap <expr> <buffer> + <SID>TodoCompeteTrigger('+', 0)
inoremap <buffer> <Tab> <C-x><C-u>
setl dictionary=expand('~/Documents/20k.txt')

" Semi-magic character insertion/completion trigger
function! <SID>TodoCompeteTrigger(triggerchar, firstcol)
  if col('.') == 1 || ! a:firstcol
    return a:triggerchar . "\<C-X>\<C-U>"
  else
    return a:triggerchar
  endif
endfunction

" Get the first token starting with a:prefix from a:line
function! s:TodoGetCompletion(prefix, _, line)
  let l:at = stridx(a:line, a:prefix)
  if l:at >= 0
    let l:atend = stridx(a:line, ' ', l:at + 1)
    return strcharpart(a:line, l:at, l:atend - l:at)
  else
    return ''
  endif
endfunction

function! TodoCompleteFunc(findstart, base)
  let l:atmatchcol = match(getline('.'), '@', col('.')-2)
  let l:plusmatchcol = match(getline('.'), '+', col('.')-2)

  if a:findstart == 1
    return l:atmatchcol == -1 ? l:plusmatchcol == -1 ? -3 : l:plusmatchcol : l:atmatchcol
  else
    return uniq(sort(map(getline('.','$'), function('s:TodoGetCompletion', [strcharpart(a:base, 0, 1)]))))
  endif
endfunction


setlocal completefunc=TodoCompleteFunc
