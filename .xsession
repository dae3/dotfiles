# id the touchpad
TOUCHPAD=$(xinput list | egrep "slave.*pointer" | grep -v XTEST | sed -e 's/^.*id=//' -e 's/\s.*$//')

# natural scrolling
SCROLLPROP=$(xinput list-props ${TOUCHPAD} |\
	awk '/Natural Scrolling Enabled \(/ { gsub(/[\(\):]/,X); print $5 }')
xinput set-prop $TOUCHPAD $SCROLLPROP 1

# tap to click
TAPPROP=$(xinput list-props ${TOUCHPAD} |\
	awk '/Tapping Enabled \(/ { gsub(/[\(\):]/,X); print $4 }')
xinput set-prop $TOUCHPAD $TAPPROP 1

. ~/.fehbg
i3
