#!/bin/bash

function cont() {
    echo Press ENTER to continue.
    read
}

function upgradeAll() {
    sudo apt update -yy
    sudo apt upgrade -yy
}

# function softwareUpdates() {

# }

clear

echo "Welcome to J2K05's CyberPatriot Script"
cont
clear

# Selector

function selector() {}
echo "Type any of the following numbers to select an action:"
    echo "1. update all packages"
    echo "2. enable automatic software updates"

    read -p "enter section number: " secnum
}

case $secnum in
1) upgradeAll; selector;
esac


exit