call ale#linter#Define('yaml', {
      \   'name': 'yaml-language-server',
      \   'lsp': 'stdio',
      \   'executable': 'node',
      \   'command': 'yaml-language-server --stdio',
      \   'project_root': 'c:\'
      \})
