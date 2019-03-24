# If you come from bash you might have to change your $PATH.
# export PATH=$HOME/bin:/usr/local/bin:$PATH

# Path to your oh-my-zsh installation.
  export ZSH="/home/deverett/.oh-my-zsh"

# Set name of the theme to load --- if set to "random", it will
# load a random theme each time oh-my-zsh is loaded, in which case,
# to know which specific one was loaded, run: echo $RANDOM_THEME
# See https://github.com/robbyrussell/oh-my-zsh/wiki/Themes
ZSH_THEME="agnoster"

# Set list of themes to pick from when loading at random
# Setting this variable when ZSH_THEME=random will cause zsh to load
# a theme from this variable instead of looking in ~/.oh-my-zsh/themes/
# If set to an empty array, this variable will have no effect.
# ZSH_THEME_RANDOM_CANDIDATES=( "robbyrussell" "agnoster" )

# Uncomment the following line to use case-sensitive completion.
# CASE_SENSITIVE="true"

# Uncomment the following line to use hyphen-insensitive completion.
# Case-sensitive completion must be off. _ and - will be interchangeable.
# HYPHEN_INSENSITIVE="true"

# Uncomment the following line to disable bi-weekly auto-update checks.
# DISABLE_AUTO_UPDATE="true"

# Uncomment the following line to change how often to auto-update (in days).
# export UPDATE_ZSH_DAYS=13

# Uncomment the following line to disable colors in ls.
# DISABLE_LS_COLORS="true"

# Uncomment the following line to disable auto-setting terminal title.
# DISABLE_AUTO_TITLE="true"

# Uncomment the following line to enable command auto-correction.
# ENABLE_CORRECTION="true"

# Uncomment the following line to display red dots whilst waiting for completion.
# COMPLETION_WAITING_DOTS="true"

# Uncomment the following line if you want to disable marking untracked files
# under VCS as dirty. This makes repository status check for large repositories
# much, much faster.
# DISABLE_UNTRACKED_FILES_DIRTY="true"

# Uncomment the following line if you want to change the command execution time
# stamp shown in the history command output.
# You can set one of the optional three formats:
# "mm/dd/yyyy"|"dd.mm.yyyy"|"yyyy-mm-dd"
# or set a custom format using the strftime function format specifications,
# see 'man strftime' for details.
# HIST_STAMPS="mm/dd/yyyy"

# Would you like to use another custom folder than $ZSH/custom?
# ZSH_CUSTOM=/path/to/new-custom-folder

# Which plugins would you like to load?
# Standard plugins can be found in ~/.oh-my-zsh/plugins/*
# Custom plugins may be added to ~/.oh-my-zsh/custom/plugins/
# Example format: plugins=(rails git textmate ruby lighthouse)
# Add wisely, as too many plugins slow down shell startup.
plugins=(git)

source $ZSH/oh-my-zsh.sh

# User configuration

# export MANPATH="/usr/local/man:$MANPATH"

# You may need to manually set your language environment
# export LANG=en_US.UTF-8

# Preferred editor for local and remote sessions
# if [[ -n $SSH_CONNECTION ]]; then
#   export EDITOR='vim'
# else
#   export EDITOR='mvim'
# fi

# Compilation flags
# export ARCHFLAGS="-arch x86_64"

# ssh
# export SSH_KEY_PATH="~/.ssh/rsa_id"

# Set personal aliases, overriding those provided by oh-my-zsh libs,
# plugins, and themes. Aliases can be placed here, though oh-my-zsh
# users are encouraged to define aliases within the ZSH_CUSTOM folder.
# For a full list of active aliases, run `alias`.
#
# Example aliases
# alias zshconfig="mate ~/.zshrc"
# alias ohmyzsh="mate ~/.oh-my-zsh"
#

docker_concleanup() {
	docker ps -a --format "{{$.ID}}-{{$.Image}}" | \
		grep -E "\-[0-9a-z]{12}" | \
		cut -d- -f1 | \
		xargs docker rm
}

docker_imagecleanup() {
	docker images --format "{{$.ID}}-{{$.Tag}}" | \
		grep '<none>' | \
		cut -d- -f1 | \
		xargs docker rmi
}

gvim() {
	case $(container_status gvim) in
		running)
			;;
		exited)
			docker start gvim
			;;
		*)
			~/containers/gvim/gvim
			;;
	esac
}

librecad() {
	case $(container_status librecad) in
		running)
			;;
		exited)
			docker start librecad
			;;
		*)
			~/containers/librecad/librecad
			;;
	esac
}

chrome() {
	case $(container_status chrome) in
		running)
			docker exec chrome chrome --user-data-dir=/data --new-window 2>1 > /dev/null
			;;
		exited)
			docker start chrome
			;;
		*)
			${HOME}/containers/chrome/chrome
			;;
	esac
}

android-studio() {
case $(container_status android-studio) in
	running)
		# nothing
		;;
	exited)
		docker start android-studio && docker exec -u0 android-studio chgrp kvm /dev/kvm
		;;
	*)
		~/containers/android-studio/android-studio
		;;
esac
}

container_status() {
	local condata=$(docker inspect --type=container "$1" 2> /dev/null | grep 'Status')
	echo ${condata%,} | cut -d: -f2 | sed -e 's/[ "]//g'
}

spotify() {
	docker run -d --rm \
		-v /etc/localtime:/etc/localtime:ro \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-e DISPLAY=unix$DISPLAY \
		--device /dev/snd:/dev/snd \
		-v $HOME/.spotify/config:/home/spotify/.config/spotify \
		-v $HOME/.spotify/cache:/home/spotify/spotify \
		--name spotify \
		spotify
}

xc() {
	xsel --clipboard | xsel --primary --input
}


ykcmd() {
	docker run \
		-it \
		--rm \
		--name yk \
		--device /dev/bus/usb:/dev/bus/usb \
		yk \
		$@
}

gimp() {
	docker run -d --rm \
		-v /etc/localtime:/etc/localtime:ro \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-e DISPLAY=unix${DISPLAY} \
		-v $XAUTHORITY:/keepass/.Xauthority:ro \
		-e XAUTHORITY="/keepass/.Xauthority" \
		-h $HOSTNAME \
		-u $(id -u) \
		-e HOME=/home \
		-v ${HOME}:/home \
		--name gimp gimp
}

inkscape() {
	docker run -d --rm \
		-v /etc/localtime:/etc/localtime:ro \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-e DISPLAY=unix${DISPLAY} \
		-h $HOSTNAME \
		-u $(id -u) \
		-e HOME=/home \
		-v ${HOME}:/home \
		--name inkscape inkscape
}

keras() {
	#docker network create keras
	#docker run -d -it -p 8888:8888 --rm --name jupyter -u$(id -u):$(id -g) tensorflow/tensorflow
	docker run -it --rm -u1000:1000 -v ~/:/home --name keras -e HOME=/home keras $@
}

h2o() {
	docker run -d --name h2o --mount type=bind,source=${HOME}/h2o,target=/data h2o > /dev/null
	docker logs h2o | tac | awk '/Open H2O/ { print $NF; exit }'
}

alias ykman="ykcmd ykman"
alias ykpers="ykcmd ykpersonalize"

alias dropbox="docker exec -it dropbox dropbox"
alias kp=~"/containers/keepass/keepass $@"
alias dps="docker ps"
alias hibernate="sudo systemctl start hibernate.target"
alias suspend="sudo systemctl start suspend.target"
alias gpgtty="gpg-connect-agent updatestartuptty /bye"
alias syslog="sudo journalctl -f"

# gpg-agent magic
export GPG_TTY="$(tty)"
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
gpg-connect-agent updatestartuptty /bye

