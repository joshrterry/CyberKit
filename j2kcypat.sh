#!/bin/bash

function cont() {
    echo Press ENTER to continue.
    read
}

function upgradeAll() {
    sudo apt update -yy
    sudo apt upgrade -yy
}

clear

echo "Welcome to J2K05's CyberPatriot Script"
cont
clear

# Selector

echo "Type any of the following numbers to select an action:"
    echo "1. secure root ssh config"
    echo "2. disable guest user"
    echo "3. check users"
    echo "4. check /etc/passwd"
    echo "5. remove games and apps"
    echo "6. configure firewall"
    echo "7. password requirements"
    echo "8. check sudoers"
    echo "9. find suspicious files"
    echo "10. services"
    echo "11. sysctl"
    echo "12. rootkits"
    echo "13. cron"
    read -p "enter section number: " secnum
    
case $secnum in
1) upgradeAll;;
esac
cont

exit