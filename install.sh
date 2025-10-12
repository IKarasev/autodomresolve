#!/usr/bin/env bash

function install ()
{
    local SCRIPTNAME=fwresolve.py
    local BKPATH=~/$SCRIPTNAME
    local INSTALLPATH=/usr/local/bin/$SCRIPTNAME
    local CONFIGDIR=/etc/fwresolve
    local CONFIGPATH=$CONFIGDIR/config.json

    if [ -e "$INSTALLPATH" ]; then
        local timestmp=$(date +"_%Y-%m-%d_%H-%M-%S")
        cp $INSTALLPATH $BKPATH$timestmp
        echo "Script backed up to: $BKPATH$timestmp"
    fi

    if [ ! -d "$CONFIGDIR" ]; then
	    echo "Creating config directory at $CONFIGDIR"
        mkdir $CONFIGDIR
        echo "Copying config template to $CONFIGPATH"
        cp ./config_template.json $CONFIGPATH
    fi

    cp $SCRIPTNAME $INSTALLPATH
    chmod 710 "$INSTALLPATH"
    echo "Script installed to: $INSTALLPATH"
}

install
