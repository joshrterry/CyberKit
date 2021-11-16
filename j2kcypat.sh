#!/bin/bash

hackingTools=("wireshark" "nmap" "netcat" "sqlmap" "hydra" "john" "yersinia" "telnetd" "medusa" "pompem" "goldeneye" "packit" "themole" "metasploit" "aircrack-ng" "autopsy" "lynis" "fierce" "samba" "apache2" "nginx" "zenmap" "crack" "fakeroot" "logkeys")
keyWords=("exploit" "vulnerability" "crack" "capture" "logger" "inject" "game" "online")

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

    # echo "CHANGE THE FOLLOWING SETTINGS IN /etc/login.defs"
    # echo ""
    # echo "PASS_MAX_DAYS 90"
    # echo "PASS_MIN_DAYS 10"
    # echo "PASS_WARN_AGE 7"
    # gedit /etc/login.defs
    # cont
    # echo "CHANGE THE FOLLOWING SETTINGS IN /etc/pam.d/common-password"
    # echo ""
    # echo "Ensure sha512 encryption is being used"
    # echo "Add 'remember=5' to the end of the line that has 'pam_unix.so' in it"
    # echo "Add 'minlen=8' to the end of the line that has 'pam_unix.so' in it"
    # echo "Add 'ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' to the end of the line that has 'pam_cracklib.so' in it"
    # gedit /etc/pam.d/common-password
    # cont
    # echo "CHANGE THE FOLLOWING SETTINGS IN /etc/pam.d/common-auth"
    # echo ""
    # echo "Add this to the end of the file:"
    # echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800"
    # gedit /etc/pam.d/common-auth
}

function removeHackingTools() {
    clear
    echo "Searching for hacking tools..."

    #Prompt user to delete any hacker tools found on system

    for i in "${hackingTools[@]}"; do
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
        clear
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

function disableFTP {
    clear
    while promptYN -n "remove another ftp service?"; do
    echo "The following ftp services are in use:"
    dpkg -l | grep ftp
    read -p "which ftp service would you like to purge: " ftpservice
    if promptYN -n "purge $ftpservice?"; then
        sudo apt purge $ftpservice -yy
    fi
    done
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
    echo "Ensure that the only user with a UID of 0 is the root"
    echo "username:uid"
    cat /etc/passwd | cut -f1,3 -d:
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
    echo "11. secure ssh"
    echo "12. disable ftp"
    echo "13. check services"
    echo "14. check /etc/passwd"
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
9) removeHackingTools;;
10) passwordPolicy;;
11) secureSSH;;
12) disableFTP;;
13) checkServices;;
14) checkUID0;;
esac


exit

# Things to add:
# - Check file permissions
# - Check related Sudo files (Compare with exemplar files?) - diff command
# DONE Password hashing algorithm
# - Check groups
# - Improve finding hacking tools and other unauthorized apps
# - Conf files
# - fix service checker to use systemctl
