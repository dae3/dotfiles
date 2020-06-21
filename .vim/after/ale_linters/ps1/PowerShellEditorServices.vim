function! <SID>GetTemp()
  " On Windows, environ() can explode
  " https://github.com/neovim/neovim/issues/11881
  try
    if has_key(environ(), 'TEMP')
      let l:temp = environ()['TEMP']
    elseif has_key(environ(), 'TMP')
      let l:temp = environ()['TMP']
    else
      let l:temp='c:\'
    endif
  catch  /^Vim\%((\a\+)\)\=:E685/
    let l:temp='c:\'
  endtry

  if strridx(l:temp, '\') != strlen(l:temp) - 1
    let l:temp = l:temp . '\'
  endif

  return l:temp
endfunction

function! <SID>GetProjectRoot(bufnr)
  return 'c:\'
endfunction

function! <SID>GetCommand(bufnr)
  let l:pses_log=<SID>GetTemp() . 'pses-' . a:bufnr . '.log'
  let l:pses_sess=<SID>GetTemp() . 'pses-session-' . a:bufnr . '.json'

  " TODO: find PowerShellEditorServices rather than have it hardcoded
  let l:psespath='c:\Users\daniel.everett\Documents\tools\PowerShellEditorServices\'

  let l:cmd = 'pwsh -ExecutionPolicy Bypass -NoLogo -NoProfile' .
        \ ' -Command "' .  l:psespath . 'PowerShellEditorServices\Start-EditorServices.ps1' .
        \ ' -BundledModulesPath ' .  l:psespath .
        \ ' -LogPath ' . l:pses_log .
        \ ' -SessionDetailsPath ' . l:pses_sess .
        \ ' -FeatureFlags @() -AdditionalModules @() -HostName ale -HostProfileId ale -HostVersion 1.0.0 -Stdio -LogLevel Normal"'

  return l:cmd
endfunction

call ale#linter#Define('ps1', {
      \   'name': 'PowerShellEditorServices',
      \   'lsp': 'stdio',
      \   'executable': 'pwsh',
      \   'command': function('<SID>GetCommand'),
      \ 'output_stream': 'both',
      \   'project_root': 'c:\'
      \})
