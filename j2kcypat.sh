#!/bin/bash

addingUsers = 0

function cont() {
    echo Press ENTER to continue.
    read
}

function promptYN() {
    prompt="$1 [Y/n] "
    if [[ "$1" == "-n" ]]; then
        prompt="$2 [y/N] "
    fi

    read -p "$prompt" yn

    if [[ "$1" == "-n" ]]; then
        if [[ -z "$yn" ]]; then
            return 1
        else
            return `[[ $yn =~ ^[yY]$ ]]`
        fi
    else
        return `[[ $yn =~ ^[yY]?$ ]]`
    fi
}

function upgradeAll() {
    sudo apt update -yy
    sudo apt upgrade -yy
}

function softwareUpdates() {
    software-properties-gtk
    echo "CHANGE THE FOLLOWING SETTING UNDER UPDATES:"
    echo "Automatically check for updates \e[1;41m Daily \e [0m"
}

function checkUsers() {
    if promptYN -n "enter all users?"; then
    inputUsers
    else
    echo "skipped adding new users";
    fi
}

function inputUsers() {
    
    echo -n > /home/script/passwds.txt
    echo -n > /home/script/admins.txt

    echo "type out all users, separated by lines"
    echo "press ENTER again once you are finished"

    while isReading == true

    

}

}

clear

echo "Welcome to J2K05's CyberPatriot Script"
cont
clear

# Selector

function selector() {
echo "Type any of the following numbers to select an action:"
    echo "1. update all packages"
    echo "2. enable automatic software updates"
    echo "3. check users"
    read -p "enter section number: " secnum
}

selector
case $secnum in
1) upgradeAll; selector;
3) 
esac


exit