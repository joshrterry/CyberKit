#!/bin/bash

############################################ VARIABLES ############################################

PROHIBITEDSOFTWARE=("wireshark" "nmap" "netcat" "sqlmap" "hydra" "john" "yersinia" "telnetd" "medusa" "pompem" "goldeneye" "packit" "themole" "metasploit" "aircrack-ng" "autopsy" "lynis" "fierce" "samba" "apache2" "nginx" "zenmap" "crack" "fakeroot" "logkeys" "aircrack-ng" "libzc6" "ncrack" "xserver-xorg*" "avahi-daemon" "cups" "isc-dhcp-server" "slapd" "nfs-kernel-server" "bind9" "vsftpd" "dovecot-imapd" "dovecot-pop3d" "squid" "snmpd" "autofs")
KEYWORDS=("exploit" "vulnerability" "crack" "capture" "logger" "inject" "game" "online" "ftp" "gaming" "hack" "sniff" "intercept" "port")
SIXFOURFOUR=("/etc/passwd" "/etc/passwd-" "/etc/group" "/etc/group-" "/etc/issue.net" "/etc/issue" "/etc/motd")
SIXFORTY=("/etc/shadow" "/etc/shadow-" "/etc/gshadow" "/etc/gshadow-" "/etc/sudoers")
SIXHUNDRED=("/etc/crontab")
SEVENHUNDRED=("/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/etc/cron.d")
INSECURESERVICES=("avahi-daaemon.service" "avahi-daemon.socket" "opemsmtpd.service" )

########################################### SCRIPT TOOLS ###########################################

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

######################################## HARDENING FUNCTIONS ########################################

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
            if grep $username configs/passwds.txt > /dev/null; then
                echo "$username found in configs/passwds.txt, skipping"
            elif promptYN -n "$username not found in configs/passwds.txt, remove?"; then
                deluser --remove-home $username
                echo "$username deleted."
            fi
        done
    fi

        # get list of sudoers
    if promptYN -n "check admin?"; then
        for username in `cat /etc/group | grep sudo | cut -d: -f4 | tr ',' '\n'`; do
            if grep $username configs/admins.txt; then
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

    if promptYN -n "check groups?"; then
        checkGroups
    fi

    cont
    checkUID0
}

function inputUsers() {
    touch configs/passwds.txt
    touch configs/admins.txt
    > configs/passwds.txt
    > configs/admins.txt
    
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
                echo "$username" >> configs/admins.txt
            fi 

            echo "${username}:0ldScona2021!" >> configs/passwds.txt

    done

    echo "content of \"configs/passwds.txt\":"
    cat configs/passwds.txt

    if promptYN "change all user passwords?"; then
        cat configs/passwds.txt | chpasswd
    fi
    
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
    if promptYN -n "disable local root login?"; then
        clear
        sudo usermod -p '!' root
        echo "root login disabled"
    fi

    if promptYN -n "check for password protection?"; then
        clear
        SUDOGREP=$(grep NOPASSWD /etc/sudoers)
        if echo $SUDOGREP | grep -q NOPASSWD; then
            echo "password protecting sudo..."
            sudo sed -i "s/$SUDOGREP//" /etc/sudoers
            else
            echo "sudo is already password protected"
        fi
    fi

    if promptYN -n "check sudoers.d directory?"; then
        clear
        echo "searching /etc/sudoers.d/"
        ls -l /etc/sudoers.d/
    fi

    if promptYN -n "check sudoers file?"; then
        clear
        echo "displaying differences in sudoers file:"
        echo ""
        diff configs/sudoers.txt /etc/sudoers
        if promptYN -n "modify sudoers file?"; then
            sudo visudo
        fi
    fi

    if promptYN -n "check /etc/sudoers.d/README?"; then
        clear
        echo "displaying differences in /etc/sudoers.d/README"
        diff configs/sudoersd.txt /etc/sudoers.d/README
        if promptYN -n "overwrite /etc/sudoers.d/README?"; then
            echo "backing up to cypat/backups..."
            cp /etc/login.defs backups/login.defs
            echo "overwriting login.defs..."
            cat configs/login.defs > /etc/login.defs
        fi
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
    echo "searching for hacking tools and potential vulnerabilities..."

    # prompt user to delete any prohibited software found on machine

    for i in "${PROHIBITEDSOFTWARE[@]}"; do
        clear
        if dpkg -l | grep -i $i; then
            if promptYN -n "remove $i?"; then
                sudo apt purge $i -yy
            fi
        fi
    done

    clear

    for i in "${KEYWORDS[@]}"; do
        clear
        echo "searching for packages with '$i' in the description"
        if dpkg -l | grep -i $i; then
            while promptYN -n "remove a package with this key word?"; do
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
        echo "disabling empty passwords..."
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

    sudo service ssh restart

}

function checkServices {
    clear

    if promptYN "check known insecure services?"; then
        for i in "${INSECURESERVICES[@]}"; do
            clear
            if systemctl list-units --full -all | grep -Fi $i; then
                if promptYN -n "stop $i?"; then
                    systemctl stop $i
                fi
            fi
        done
    fi

   if promptYN "check all services?"; then
        service --status-all
    fi
    echo "Check service configuration files for required services in /etc."
    echo "Usually a wrong setting in a config file for sql, apache, etc. will be a point."
}

function checkUID0() {

    for username in `cat /etc/passwd | cut -f1,3 -d: | grep -v "root:0" | grep ":0" | cut -f1 -d:`; do
        if promptYN "$username has a UID of 0! Change this users UID"; then
        sudo gedit /etc/passwd    
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

function filePermissions() {

for i in "${SIXFOURFOUR[@]}"; do
    if test -e "$i"; then
        sudo chown root:root $i
        sudo chmod 644 $i
    fi
done

for i in "${SIXFORTY[@]}"; do
    if test -e "$i"; then
        sudo chown root:root $i
        sudo chmod 640  $i
    fi
done

for i in "${SIXHUNDRED[@]}"; do
    if test -e "$i"; then
        sudo chown root:root $i
        sudo chmod 600 $i
    fi
done

for i in "${SEVENHUNDRED[@]}"; do
    if test -e "$i"; then
        sudo chown root:root $i
        sudo chmod 700 $i
    fi
done

echo "file permissions have been set"

}

function checkMalware() {
    clear
    if promptYN "install clamav?"; then
        sudo apt install clamav
        sudo killall freshclam
        sudo freshclam
        if promptYN "would you like to scan system for malware? (NOTE: this may take a while)"; then
            echo "infected files will be moved to ~/cypat/clamscanresults"
            cont
            clamscan -r --move=clamscanresults
        fi
    fi
    if promptYN "check clamscan results?"; then
        ls -la clamscanresults/
        if promptYN "empty directory?"; then
            sudo rm -r clamscanresults/*
        fi
    fi
}

clear

echo "########## Welcome to J2K05's CyberPatriot Script ##########"
echo ""
echo "1. ENSURE THIS SCRIPT IS RUN AS ROOT"
echo "2. RUN SCRIPT IN ~/cypat"
echo "3. COMPLETE FORENSICS QUESTIONS FIRST"
echo "4. SET FIREFOX SETTINGS THROUGH GUI"
echo ""

if [ ! -d passwords/ ]; then
    sudo mkdir passwords
fi
if [ ! -d backups/ ]; then
    sudo mkdir backups
fi
if [ ! -d clamscanresults/ ]; then
    sudo mkdir clamscanresults
fi

cont
clear

########################################### SELECTOR ###########################################

function selector() {
    clear
    echo "Type any of the following numbers to select an action:"
        echo "1. update all packages"
        echo "2. enable automatic software updates"
        echo "3. check users and groups"
        #https://linuxconfig.org/how-to-turn-on-off-ip-forwarding-in-linux
        echo "4. disable IPv4 forwarding"
        #https://phpraxis.wordpress.com/2016/09/27/enable-sudo-without-password-in-ubuntudebian/
        echo "5. secure sudo"
        echo "6. search home directory for unwanted files"
        echo "7. enable and configure ufw"
        echo "8. remove prohibited software"
        echo "9. set password policy"
        echo "10. secure ssh"
        echo "11. check services"
        echo "12. set file permissions"
        echo "13. check for malware"
        read -p "enter section number: " secnum
}

selector
case $secnum in
1) upgradeAll;;
2) softwareUpdates;;
3) checkUsers;;
4) disableIPv4;;
5) secureSudo;;
6) searchHome;;
7) ufwEnable;;
8) removeProhibitedSoftware;;
9) passwordPolicy;;
10) secureSSH;;
11) checkServices;;
12) filePermissions;;
13) checkMalware;;
esac


exit

# Checklist:
# DONE Check file permissions
# DONE Check related Sudo files (Compare with exemplar files?) - diff command
# DONE Password hashing algorithm
# DONE Check groups
# DONE Improve finding hacking tools and other unauthorized apps
# WIP fix service checker
# - scrape readme for authorized users
# - cron