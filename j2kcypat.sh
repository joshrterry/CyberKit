#!/bin/bash

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
    clear
    sudo apt update -yy
    sudo apt upgrade -yy
}

function softwareUpdates() {
    clear
    echo "CHANGE THE FOLLOWING SETTING UNDER UPDATES:"
    echo ""
    echo "CHECK Important security Updates"
    echo "CHECK Recoomended updates"
    echo "Automatically check for updates: DAILY"
    echo "When there are security updates: DOWNLOAD AND INSTALL AUTOMATICALLY"
    echo "When there are other updates: DISPLAY IMMEDIATELY"
    software-properties-gtk

}

function checkUsers() {
    clear
    if promptYN -n "enter all users?"; then
    inputUsers
    else
    echo "skipped adding new users";
    fi

        # checks if the provided user from /etc/passwd was given by the user.
    # i.e. is there a user on the system that should not be there
    if promptYN -n "check users in /etc/passwd?"; then
        for username in `cat /etc/passwd | cut -d: -f1`; do
            if grep $username /home/script/passwds.txt > /dev/null; then
                echo "$username found in /home/script/passwds.txt, skipping"
            elif promptYN -n "$username not found in /home/script/passwds.txt, remove?"; then
                deluser --remove-home $username
                echo "$username deleted."
            fi
        done
    fi
}

function inputUsers() {
    touch /home/script/passwds.txt
    touch /home/script/admins.txt
    
    clear

    echo "type out all users, separated by lines"
    echo ""

    while promptYN -n "add another user?"; do

        read -p "username: " username
        echo "checking for $username"

            # if user not found
            if cat /etc/passwd | grep $username &>/dev/null; then
                echo "$username exists in /etc/passwd"
            elif promptYN "$username not found in /etc/passwd. create user $username?"; then
            adduser "$username"
            fi

            if promptYN -n "is $username an admin?"; then
                adduser "$username" sudo #add to sudo group
                adduser "$username" adm
                echo "$username added to sudo and adm groups"
                echo "$username" >> /home/script/admins.txt
            fi 

            echo "${username}:0ld\$cona2021!" >> /home/script/passwds.txt

    done

    echo "content of \"/home/script/passwds.txt\":"
    cat /home/script/passwds.txt

    if promptYN "change all user passwords?"; then
        cat /home/script/passwds.txt | chpasswd
    fi
    
}

function firefoxSettings() {
    clear
    echo "CHANGE THE FOLLOWING SETTINGS UNDER Preferences -> Privacy & Security"
    echo "Set DO NOT TRACK to ALWAYS"
    echo "Delete cookies and site data when Firefox is closed"
    echo "Don't save passwords"
    echo "Block pop-up windows"
    echo "Warn you when websites try to install add-ons"

    firefox


}

function searchHome() {

    clear
    if promptYN -n "install tree"; then
    sudo apt install tree -yy
    clear
    echo "Searching home folder..."
    sudo tree ~
    else 
    echo "unable to search home folder";
    fi
}

function secureSudo() {

    clear
    if sudo cat /etc/sudoers | grep -q NOPASSWD; then
    sudo visudo
    echo "Remove (username ALL=(ALL) NOPASSWD:ALL)"
    else
    echo "sudo is already password protected"
    fi

}

function disableIPv4() {
    clear
    if sudo cat /proc/sys/net/ipv4/ip_forward | grep -q 1; then
    echo "DISABLING IPV4 FORWARDING"
    echo 0 > /proc/sys/net/ipv4/ip_forward
    else
    echo "IPV4 Forwarding already disabled"
    fi
}

function ufwEnable() {
    clear
    echo "Enabling UFW with settings: DENY INCOMING & ALLOW OUTGOING"
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw enable
    echo "UFW ENABLED"
}

function passwordPolicy() {
    clear
    if promptYN -n "install libpam-cracklib"; then
    sudo apt install libpam-cracklib -yy  
    fi
    echo "CHANGE THE FOLLOWING SETTINGS IN /etc/login.defs"
    echo ""
    echo "PASS_MAX_DAYS 90"
    echo "PASS_MIN_DAYS 10"
    echo "PASS_WARN_AGE 7"
    gedit /etc/login.defs
    cont
    echo "CHANGE THE FOLLOWING SETTINGS IN /etc/pam.d/common-password"
    echo ""
    echo "Add 'remember=5' to the end of the line that has 'pam_unix.so' in it"
    echo "Add 'minlen=8' to the end of the line that has 'pam_unix.so' in it"
    echo "Add 'ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' to the end of the line that has 'pam_cracklib.so' in it"
    gedit /etc/pam.d/common-password
    cont
    echo "CHANGE THE FOLLOWING SETTINGS IN /etc/pam.d/common-auth"
    echo ""
    echo "Add this to the end of the file:"
    echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800"
    gedit /etc/pam.d/common-auth
}

function removeHackingTools() {
    clear
    echo "Searching for hacking tools..."

    #Prompt user to delete any hacker tools found on system
    if dpkg -l | grep wireshark; then
        if promptYN -n "remove wireshark"; then
        sudo apt purge wireshark -yy
        sudo apt purge wireshark-common -yy

        fi
    fi
    
        if dpkg -l | grep nmap; then
        if promptYN -n "remove nmap"; then
        sudo apt purge nmap -yy
        fi
    fi

        if dpkg -l | grep netcat; then
        if promptYN -n "remove netcat"; then
        sudo apt purge netcat -yy
        fi
    fi

        if dpkg -l | grep sqlmap; then
        if promptYN -n "remove sqlmap"; then
        sudo apt purge sqlmap -yy
        fi
    fi

        if dpkg -l | grep hydra; then
        if promptYN -n "remove hydra"; then
        sudo apt purge hydra -yy
        fi
    fi

        if dpkg -l | grep john; then
        if promptYN -n "remove john the ripper"; then
        sudo apt purge john -yy
        fi
    fi

        if dpkg -l | grep yersinia; then
        if promptYN -n "remove yersinia"; then
        sudo apt purge yersinia -yy
        fi
    fi

    if dpkg -l | grep telnetd; then
        if promptYN -n "remove telnetd"; then
        sudo apt purge telnetd -yy
        fi
    fi

        if dpkg -l | grep medusa; then
        if promptYN -n "remove medusa"; then
        sudo apt purge yersinia -yy
        fi
    fi

}

clear

echo "Welcome to J2K05's CyberPatriot Script"
sudo mkdir /home/script
cont
clear

# Selector

function selector() {
    clear
echo "Type any of the following numbers to select an action:"
    echo "1. update all packages"
    echo "2. enable automatic software updates"
    echo "3. check users"
    echo "4. firefox settings"
    #https://linuxconfig.org/how-to-turn-on-off-ip-forwarding-in-linux
    echo "5. disable IPv4 forwarding"
    #https://phpraxis.wordpress.com/2016/09/27/enable-sudo-without-password-in-ubuntudebian/
    echo "6. ensure sudo is password protected"
    echo "7. search home directory for unwanted files"
    echo "8. enable and configure ufw"
    echo "9. remove hacking tools"
    echo "10. set password policy"
    read -p "enter section number: " secnum
}

selector
case $secnum in
1) upgradeAll; selector;;
2) softwareUpdates;;
3) checkUsers; selector;;
4) firefoxSettings;;
5) disableIPv4;;
6) secureSudo;;
7) searchHome; selector;;
8) ufwEnable; selector;;
9) removeHackingTools; selector;;
10) passwordPolicy;;
esac


exit
