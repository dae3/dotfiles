# id the touchpad
TOUCHPAD=$(xinput list | egrep "slave.*pointer" | grep -v XTEST | sed -e 's/^.*id=//' -e 's/\s.*$//')

# natural scrolling
xinput set-prop $TOUCHPAD 274 1

# tap to click
xinput set-prop $TOUCHPAD 284 1

i3
