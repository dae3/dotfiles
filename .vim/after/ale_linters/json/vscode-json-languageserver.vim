call ale#linter#Define('json', {
      \   'name': 'vscode-json-languageserver',
      \   'lsp': 'stdio',
      \   'executable': 'node',
      \   'command': '%e c:\users\daniel.everett\.vim\after\ale_linters\json\node_modules\vscode-json-languageserver\bin\vscode-json-languageserver --stdio',
      \   'project_root': 'c:\'
      \})
