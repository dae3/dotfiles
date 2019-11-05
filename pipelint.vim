function! Pipelint(buffer)

	let l:jenkins='http://localhost:8080'
	"let l:crumb=system('curl -s "' . l:jenkins . '/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)"')

	let l:rawlint = systemlist(
				\'curl -s -X POST -F "jenkinsfile=<-" ' . l:jenkins . '/pipeline-model-converter/validate',
				\getbufline(a:buffer, 1, '$')
				\)

	call setqflist(map(filter(l:rawlint, 'v:val =~ "WorkflowScript"'), function('Pipelint_map', [a:buffer])), 'r')
endfunction

function! Pipelint_map(b, k, v)
	" format returned from Jenkins linter is
	" WorkflowScript: 1: unexpected token:  @ line 1, column 2.
	" match 1: ecount, 2: error, 3: line, 4: column
	let l:splitlint=matchlist(a:v, '^WorkflowScript:\s\+\(\d\+\):\s\+\(.\+\)\s\+@ line \(\d\+\), column \(\d\+\)\.')
	return { 'nr': a:k, 'bufnr': a:b, 'lnum': l:splitlint[3], 'text': l:splitlint[2], 'col': l:splitlint[4] }
endfunction

function! JenkinsJobLog(pipeline, branch, jobnr)
	let l:url = 'http://localhost:8080/job/' . a:pipeline . '/job/' . a:branch . '/' . a:jobnr . '/consoleText'
	normal! ggdG
	call append(1, systemlist('curl -s ' . l:url))
	normal! G
endfunction

