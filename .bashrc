
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

PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\] \$ '
PATH=$PATH:~/bin

# gpg-agent magic
export GPG_TTY="$(tty)"
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
gpg-connect-agent updatestartuptty /bye

