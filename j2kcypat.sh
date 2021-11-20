#!/bin/bash

hackingTools=("wireshark" "nmap" "netcat" "sqlmap" "hydra" "john" "yersinia" "telnetd" "medusa" "pompem" "goldeneye" "packit" "themole" "metasploit" "aircrack-ng" "autopsy" "lynis" "fierce" "samba" "apache2" "nginx" "zenmap" "crack" "fakeroot" "logkeys")
keyWords=("exploit" "vulnerability" "crack" "capture" "logger" "inject" "game" "online" "ftp" "gaming" "hack" "sniff" "intercept")

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
    echo "CHECK Recommended updates"
    echo "Automatically check for updates: DAILY"
    echo "When there are security updates: DOWNLOAD AND INSTALL AUTOMATICALLY"
    echo "When there are other updates: DISPLAY IMMEDIATELY"
    echo ""
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
        for username in `cat /etc/passwd | grep /bin/bash | cut -d: -f1`; do
            if grep $username /home/script/passwds.txt > /dev/null; then
                echo "$username found in /home/script/passwds.txt, skipping"
            elif promptYN -n "$username not found in /home/script/passwds.txt, remove?"; then
                deluser --remove-home $username
                echo "$username deleted."
            fi
        done
    fi

        # get list of sudoers
    if promptYN -n "check admin?"; then
        for username in `cat /etc/group | grep sudo | cut -d: -f4 | tr ',' '\n'`; do
            if grep $username /home/script/admins.txt; then
                echo "$username is a valid admin, skipping"
            elif promptYN "$username is in the sudo group but not a valid sudoer, remove from sudo?"; then
                deluser $username sudo
                echo "$username removed from sudo group."
                if cat /etc/group | grep adm | grep $username && promptYN "user also in \"adm\" group, remove?"; then
                    deluser $username adm
                    echo "$username removed from adm group."
                fi
            fi
        done
    fi

    if promptYN -n "check uid 0?"; then 
        checkUID0
        fi

    if promptYN -n "check groups?"; then
        checkGroups
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

            echo "${username}:0ldScona2021!" >> /home/script/passwds.txt

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
    echo "Set firefox as the default browser"
    echo ""
    firefox
}

function searchHome() {
    clear
    if promptYN -n "install tree"; then
    sudo apt install tree -yy
    echo "Searching home directory..."
    sudo tree /home/
    else 
    echo "unable to search home directory";
    fi
}

function secureSudo() {
    clear
    sudogrep=$(grep NOPASSWD /etc/sudoers)
    if echo $sudogrep | grep -q NOPASSWD; then
        echo "PASSWORD PROTECTING SUDO..."
        sudo sed -i "s/$sudogrep//" /etc/sudoers
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
    echo "creating backups directory..."
    mkdir backups
    clear
    if promptYN -n "install libpam-cracklib"; then
    sudo apt install libpam-cracklib -yy  
    fi
    
    echo "displaying differences in login.defs file"
    diff configs/login.defs /etc/login.defs
    if promptYN -n "overwrite login.defs?"; then
        echo "backing up to cypat/backups..."
        cp /etc/login.defs backups/login.defs
        echo "overwriting login.defs..."
        cat configs/login.defs > /etc/login.defs
    fi

    echo "displaying differences in common-password file"
    diff configs/common-password /etc/pam.d/common-password
    if promptYN -n "overwrite common-password?"; then
        echo "backing up to cypat/backups..."
        cp /etc/pam.d/common-password backups/common-password
        echo "overwriting common-password..."
        cat configs/common-password > /etc/pam.d/common-password
    fi

    echo "displaying differences in common-auth file"
    diff configs/common-auth /etc/pam.d/common-auth
    if promptYN -n "overwrite common-auth?"; then
        echo "backing up to cypat/backups..."
        cp /etc/pam.d/common-auth backups/common-auth
        echo "overwriting common-auth..."
        cat configs/common-auth > /etc/pam.d/common-auth
    fi

}

function removeProhibitedSoftware() {
    clear
    echo "Searching for hacking tools..."

    #Prompt user to delete any hacker tools found on system

    for i in "${hackingTools[@]}"; do
        clear
        if dpkg -l | grep -i $i; then
            if promptYN -n "remove $i?"; then
                sudo apt purge $i -yy
            fi
        fi
    done

    clear

    for i in "${keyWords[@]}"; do
        clear
        echo "searching for packages with '$i' in the description"
        if dpkg -l | grep -i $i; then
            while promptYN -n "remove a package with this key word?"; do
            dpkg -l | grep -i $i
            read -p "which package would you like to remove: " package
        if promptYN -n "remove $package"; then
            sudo apt purge $package -yy
        fi
        done
    fi
    done

    sudo apt autoremove

}

function secureSSH {

    if sudo cat /etc/ssh/ssh_config | grep "PermitEmptyPasswords no" | grep -v '^#'; then
        echo "PermitEmptyPasswords is already disabled"        
    else
        echo "DISABLING EMPTY PASSWORDS..."
        echo "PermitEmptyPasswords no" >> /etc/ssh/ssh_config
    fi

    if sudo cat /etc/ssh/ssh_config | grep "Protocol" | grep -v '^#'; then
        echo "ENSURE ONLY Protocol 2 IS IN USE"
        gedit /etc/ssh/ssh_config
    else
        echo "SSH protocol 1 is already disabled"
    
    fi
    
    if sudo cat /etc/ssh/ssh_config | grep "PermitRootLogin no" | grep -v '^#'; then 
        echo "PermitRootLogin is already disabled"
     else 
        echo "DISABLING ROOT LOGIN..."
        echo "PermitRootLogin no" >> /etc/ssh/ssh_config
    fi

}

function checkServices {
    clear
   if promptYN "check services?"; then
        service --status-all | less
    fi
    echo "Check service configuration files for required services in /etc."
    echo "Usually a wrong setting in a config file for sql, apache, etc. will be a point."
}

function checkUID0() {

    for username in `cat /etc/passwd | cut -f1,3 -d: | grep -v "root:0" | grep ":0" | cut -f1 -d:`; do
        if promptYN "$username has a UID of 0! Change this users UID?"; then
            UID
            sudo cat /etc/passwd | grep $username | sudo sed -i s/$username:x:0:0:/$username:x:1100:1100:/
            sudo cat /etc/passwd | grep $username | sudo sed -i s/$username:x:0:....:/$username:x:1100:1100:/
            echo "removed UID 0 from $username"
        fi
    done
    
}

function checkGroups() {
    cat /etc/group | grep ":1...:"
    while promptYN "would you like to delete a group?"; do
        read -p "which group would you like to delete: " group
        sudo delgroup $group
        echo "$group has been removed"
    done

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
    echo "3. check users and groups"
    echo "4. firefox settings"
    #https://linuxconfig.org/how-to-turn-on-off-ip-forwarding-in-linux
    echo "5. disable IPv4 forwarding"
    #https://phpraxis.wordpress.com/2016/09/27/enable-sudo-without-password-in-ubuntudebian/
    echo "6. ensure sudo is password protected"
    echo "7. search home directory for unwanted files"
    echo "8. enable and configure ufw"
    echo "9. remove prohibited software"
    echo "10. set password policy"
    echo "11. secure ssh"
    echo "12. check services"
    read -p "enter section number: " secnum
}

selector
case $secnum in
1) upgradeAll;;
2) softwareUpdates;;
3) checkUsers;;
4) firefoxSettings;;
5) disableIPv4;;
6) secureSudo;;
7) searchHome;;
8) ufwEnable;;
9) removeProhibitedSoftware;;
10) passwordPolicy;;
11) secureSSH;;
12) checkServices;;
esac


exit

# Checklist:
# - Check file permissions
# - Check related Sudo files (Compare with exemplar files?) - diff command
# DONE Password hashing algorithm
# - Check groups
# DONE Improve finding hacking tools and other unauthorized apps
# - Conf files
# - fix service checker to use systemctl
# - scrape readme for authorized users
