#!/usr/bin/env bash

function install ()
{
    local SCRIPTNAME=fwresolve.py
    local BKPATH=~/$SCRIPTNAME
    local INSTALLPATH=/usr/local/bin/$SCRIPTNAME

    if [ -e "$INSTALLPATH" ]; then
        local timestmp=$(date +"_%Y-%m-%d_%H-%M-%S")
        cp $INSTALLPATH $BKPATH$timestmp
        echo "Script backed up to: $BKPATH$timestmp"
    fi

    cp $SCRIPTNAME $INSTALLPATH
    chmod 710 "$INSTALLPATH"
    echo "Script installed to: $INSTALLPATH"
}

install
