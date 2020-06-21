setlocal foldmethod=syntax

let b:ale_linters = [ 'gopls' ]
let b:ale_fixers = [ 'gofmt' ]
let b:ale_fix_on_save=1

function! <SID>TabCompleteTrigger()
  if col(".") == 1
    return "\<tab">
  else
    return "\<C-X>\<C-O>"
  endif
endfunction

inoremap <buffer> <expr> <tab> <SID>TabCompleteTrigger()


setl omnifunc=ale#completion#OmniFunc
