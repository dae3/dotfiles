
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
	case $(container_status chromium) in
		running)
			docker exec chromium chromium --user-data-dir=/data --new-window 2>1 > /dev/null
			;;
		exited)
			docker start chromium
			;;
		*)
			~/containers/chromium/chromium
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
	docker run -d \
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
	docker run -d \
		-v /etc/localtime:/etc/localtime:ro \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-e DISPLAY=unix$DISPLAY \
		-v /media/data:/root/Pictures \
		--name gimp gimp
}

alias ykman="ykcmd ykman"
alias ykpers="ykcmd ykpersonalize"

alias dropbox="docker exec -it dropbox dropbox"
alias kp=~"/containers/keepass/keepass $@"
alias dps="docker ps"
alias hibernate="sudo systemctl start hibernate.target"
alias gpgtty="gpg-connect-agent updatestartuptty /bye"
alias syslog="sudo journalctl -f"

PS1="${debian_chroot:+($debian_chroot)}\u@\h:\w(\j)\$ "
PATH=$PATH:~/bin

# gpg-agent magic
export GPG_TTY="$(tty)"
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
gpg-connect-agent updatestartuptty /bye

