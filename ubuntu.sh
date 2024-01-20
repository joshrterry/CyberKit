#!/bin/bash

############################################ VARIABLES ############################################

PROHIBITEDSOFTWARE=("wireshark*" "nmap" "netcat" "sqlmap" "hydra" "john" "yersinia" "telnet" "telnetd" "medusa" "pompem" "goldeneye" "packit" "themole" "metasploit" "aircrack" "autopsy" "lynis" "fierce" "samba" "apache2" "nginx" "zenmap" "crack" "fakeroot" "logkeys" "aircrack-ng" "libzc6" "ncrack" "avahi-daemon" "cups*" "isc-dhcp-server" "slapd" "nfs-kernel-server" "bind9" "vsftpd" "dovecot-imapd" "dovecot-pop3d" "squid" "snmpd" "autofs" "rsync" "nis" "rsh-client" "talk" "ldap-utils" "rpcbind" "opensmtpd" "dos" "wpscan" "skipfish" "maltego" "nessus" "beef" "apktool" "snort" "xinetd" "doona" "proxychains" "xprobe")
KEYWORDS=("exploit" "vulnerability" "crack" "capture" "logger" "inject" "game" "online" "ftp" "gaming" "hack" "sniff" "intercept" "port" "phish" "forensics" "scan" "penetration" "fuzz" "proxy" "fingerprinting")
SIXFOURFOUR=("/etc/passwd" "/etc/passwd-" "/etc/group" "/etc/group-" "/etc/issue.net" "/etc/issue" "/etc/motd")
SIXFORTY=("/etc/shadow" "/etc/shadow-" "/etc/gshadow" "/etc/gshadow-" "/etc/sudoers" "/etc/cron.allow")
SIXHUNDRED=("/etc/crontab" "/etc/ssh/sshd_config" "/etc/anacrontab")
SEVENHUNDRED=("/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/etc/cron.d")
INSECURESERVICES=("avahi-daaemon.service" "avahi-daemon.socket" "opensmtpd.service")
CRITICALSOFTWARE=("rsyslog")
CRITICALSERVICES=("rsyslog")
MEDIAFILEEXTENSIONS=(".jpeg" ".jpg" ".gif" ".tiff" ".bmp" ".aac" ".mp3" ".wav" ".wma" ".ac3" ".dts" ".aiff" ".asf" ".flac" ".adpcm" ".dsd" ".lpcm" ".ogg" ".mpg" ".avi" ".mov" ".mp4" ".mp2" ".mkv" ".webm")
FILEPATH=""

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

function compareFile() {
    echo "displaying differences in $1 file"
    diff configs/$2 /etc/$1
    if promptYN -n "overwrite /etc/$1?"; then
        echo "backing up to cyberkit/backups..."
        cp /etc/$1 backups/$2
        echo "overwriting /etc/$1..."
        cat configs/$2 > /etc/$1
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
    fixApt
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
    if promptYN "enter all users?"; then
    inputUsers
    else
    echo "skipped adding new users";
    fi

        # checks if the provided user from /etc/passwd was given by the user.
    # i.e. is there a user on the system that should not be there
    if promptYN "check users in /etc/passwd?"; then
        for username in `cat /etc/passwd | grep /bin/bash | cut -d: -f1`; do
            if grep $username configs/passwds.txt > /dev/null; then
                echo "$username found in configs/passwds.txt, skipping"
            elif promptYN "$username not found in configs/passwds.txt, remove?"; then
                userdel $username
                echo "$username deleted."
            fi
        done
    fi

        # get list of sudoers
    if promptYN "check admin?"; then
        for username in `cat /etc/group | grep sudo | cut -d: -f4 | tr ',' '\n'`; do
            if grep $username configs/admins.txt; then
                echo "$username is a valid admin, skipping"
            elif promptYN "$username is in the sudo group but not a valid sudoer, remove from sudo?"; then
                gpasswd -d $username sudo
                echo "$username removed from sudo group."
                if cat /etc/group | grep adm | grep $username && promptYN "user also in \"adm\" group, remove?"; then
                    gpasswd -d $username adm
                    echo "$username removed from adm group."
                fi
            fi
        done
    fi  

    if promptYN "check groups?"; then
        checkGroups
    fi

    checkUID0
}

function inputUsers() {
    touch configs/passwds.txt
    touch configs/admins.txt
    touch configs/users.txt
    touch configs/readme.txt
    > configs/readme.txt
    > configs/passwds.txt
    > configs/admins.txt
    > configs/users.txt
    
    clear

    echo "enter users portion of readme (be sure to include any new users): "
    nano configs/readme.txt
    cat configs/readme.txt | sed -n '/Authorized Administrators/,/Authorized Users/p' | awk '{print $1}' | sed '/password:/d' | sed '/Authorized/d' | awk 'NF' > configs/users.txt
    users=$(cat configs/users.txt)

    for username in $users; do
        # read -p "username: " username
        echo "checking for $username"

        # if user not found
        if cat /etc/passwd | grep $username &>/dev/null; then
            echo "$username exists in /etc/passwd"
        elif promptYN "$username not found in /etc/passwd. create user $username?"; then
            echo "Adding user"
            useradd "$username"
        fi

        # if promptYN "is $username an admin?"; then
        adduser "$username" sudo  #add to sudo group
        adduser "$username" adm  #add to sudo group
        echo "$username added to sudo and adm groups"
        echo "$username" >> configs/admins.txt
        # fi 

        echo "${username}:0ldScona2021!" >> configs/passwds.txt

    done

    cat configs/readme.txt | sed -n '/Authorized Users/,//p' | awk '{print $1}' | sed '/password:/d' | sed '/Authorized/d' | awk 'NF' > configs/users.txt
    users=$(cat configs/users.txt)

    for username in $users; do
        # read -p "username: " username
        echo "checking for $username"

        # if user not found
            if cat /etc/passwd | grep $username &>/dev/null; then
                echo "$username exists in /etc/passwd"
            elif promptYN "$username not found in /etc/passwd. create user $username?"; then
                useradd "$username"
            fi

            echo "${username}:0ldScona2021!" >> configs/passwds.txt

    done 

    echo "content of \"configs/passwds.txt\":"
    cat configs/passwds.txt | sed '1d'

    if promptYN "change all user passwords?"; then
        cat configs/passwds.txt | sed '1d' | chpasswd
    fi
    
}

function searchHome() {
    clear
    if promptYN -n "install tree?"; then
        sudo apt install tree -yy
        echo "Searching home directory..."
        sudo tree /home/
    else 
        echo "unable to search home directory";
    fi
    if promptYN -n "install mlocate?"; then
        sudo apt install mlocate -yy
        echo "Searching for media files..."
        sudo updatedb
        for i in {"${MEDIAFILEEXTENSIONS[@]}"}; do
            echo "showing results for files ending in $i:"
            locate *$i
            cont
        done
    fi
}

function secureSudo() {
    clear
    if promptYN "disable local root login?"; then
        clear
        sudo usermod -p '!' root
        echo "root login disabled"
    fi

    if promptYN "check for password protection?"; then
        clear
        SUDOGREP=$(grep NOPASSWD /etc/sudoers)
        if echo $SUDOGREP | grep -q NOPASSWD; then
            echo "password protecting sudo..."
            sudo sed -i "s/$SUDOGREP//" /etc/sudoers
            else
            echo "sudo is already password protected"
        fi

        checknologin

        if promptYN "set root password?"; then
            sudo passwd root
        fi
    fi

    if promptYN "check sudoers.d directory?"; then
        clear
        echo "searching /etc/sudoers.d/"
        ls -l /etc/sudoers.d/
    fi

    if promptYN "check sudoers file?"; then
        clear
        echo "displaying differences in sudoers file:"
        echo ""
        diff configs/sudoers.txt /etc/sudoers
        if promptYN -n "modify sudoers file?"; then
            sudo visudo
        fi
    fi

    if promptYN "check /etc/sudoers.d/README?"; then
        clear
        compareFile sudoers.d/README sudoersd.txt
    fi

}

function disableIPv4() {
    clear
    if cat /proc/sys/net/ipv4/ip_forward | grep -q 1 || ! cmp -s /etc/sysctl.conf configs/sysctl.conf; then
        echo "DISABLING IPV4 FORWARDING"
        echo 0 > /proc/sys/net/ipv4/ip_forward
        compareFile sysctl.conf sysctl.conf
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
    echo ""

    if dpkg -l | grep iptables-persistent; then
        if promptYN "iptables-persistent is installed on this device and can conflict with ufw, would you like to remove?"; then
            sudo apt purge iptables-persistent
        fi
    fi

      if dpkg -l | grep nftables; then
        if promptYN "nftables is installed on this device and can conflict with ufw, would you like to remove?"; then
            sudo apt purge nftables
        fi
    fi

}

function passwordPolicy() {
    echo "creating backups directory..."
    clear
    if promptYN -n "install libpam-cracklib"; then
    sudo apt install libpam-cracklib -yy  
    fi

    compareFile login.defs login.defs
    compareFile pam.d/common-password common-password
    compareFile pam.d/common-auth common-auth

    if promptYN -n "set user password expiry"; then
        useradd -D -f 30
        while read admins; do
            chage -m 1 -M 90 -W 7 --inactive 30 $admins
            echo "chage set for $admins"
        done <configs/admins.txt
        while read users; do
            chage -m 1 -M 90 -W 7 --inactive 30 $users
            echo "chage set for $users"
        done <configs/users.txt
    fi

}

function checkSoftwareBeta() {
    dpkg -l | awk '{print $2}' > configs/systemmanifest.txt
    installed=$(cat configs/systemmanifest.txt)

    for app in $installed; do
        if ! cat configs/manifest.txt | grep -q $app; then
            if promptYN -n "$app not found in manifest. Uninstall?"; then
                sudo apt purge $app -yy
            fi
        fi
    done
}

function checkSoftware() {
    clear
    if promptYN "install critical packages?"; then
        apt update
        for i in "${CRITICALSOFTWARE[@]}"; do
            clear
            sudo apt install $i -yy
            echo "$i installed"
        done
    fi

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

    clear

    if promptYN "ensure PermitEmptyPasswords is set to no?"; then
        if sudo cat /etc/ssh/ssh_config | grep "PermitEmptyPasswords no" | grep -v '^#'; then
            echo ""
            echo "PermitEmptyPasswords is already disabled"        
        else
            echo "disabling empty passwords..."
            echo "PermitEmptyPasswords no" >> /etc/ssh/ssh_config
        fi
    fi

    cont
    clear

    if promptYN "ensure only SSH protocol 2 is in use?"; then
        clear
        if sudo cat /etc/ssh/ssh_config | grep "Protocol" | grep -v '^#'; then
            echo ""
            echo "ENSURE ONLY Protocol 2 IS IN USE"
            gedit /etc/ssh/ssh_config
        else
            echo "SSH protocol 1 is already disabled"
        fi
    fi

    cont
    clear
    
    if promptYN "ensure PermitRootLogin is set to no?"; then
        clear
        if sudo cat /etc/ssh/ssh_config | grep "PermitRootLogin no" | grep -v '^#'; then 
            echo ""
            echo "PermitRootLogin is already disabled"
        else 
            echo "DISABLING ROOT LOGIN..."
            echo "PermitRootLogin no" >> /etc/ssh/ssh_config
        fi
    fi

    cont
    clear

    if promptYN "compare sshd_config file?"; then
        compareFile ssh/sshd_config sshd_config
    fi

    clear

    sudo systemctl restart ssh
    sudo systemctl restart sshd

}

function checkServices {
    clear

    enableServices

    if promptYN "check known insecure services?"; then
        for i in "${INSECURESERVICES[@]}"; do
            clear
            if systemctl list-units --full -all | grep -Fi $i; then
                if promptYN -n "stop $i?"; then
                    sudo systemctl stop $i
                fi
            fi
        done
    fi

   if promptYN "check all services?"; then
        service --status-all
    fi
    echo "Check service configuration files for required services in /etc."
    echo "Usually a wrong setting in a config file for sql, apache, etc. will be a point."
    
    if promptYN "enable cron service?"; then
        systemctl --now enable cron
        if test -f "/etc/cron.deny"; then
            if promptYN "cron.deny should not exist, would you like to remove?"; then
                sudo rm /etc/cron.deny
            fi
            touch /etc/cron.allow
            chmod 640 /etc/cron.allow
            chown root:root /etc/cron.allow
        fi
    fi

    if promptYN "enable critical services?"; then
        for i in "${CRITICALSERVICES[@]}"; do
            systemctl --now enable $i
        done
    fi
}

function checkUID0() {

    for username in `cat /etc/passwd | cut -f1,3 -d: | grep -v "root:0" | grep ":0" | cut -f1 -d:`; do
        if promptYN "$username has a UID of 0! Change this users UID"; then
        sudo gedit /etc/passwd    
        fi
    done
    
}

function checknologin() {

    for username in `cat configs/passwds.txt | cut -f1 -d:`; do
        if cat /etc/passwd | grep $username | grep -q nologin; then
            echo "WARNING $username has a insecure shell, change it in /etc/passwd"
        fi
    done

    if cat /etc/passwd | grep root | grep -q nologin; then
        echo "WARNING root has a insecure shell, change it in /etc/passwd"
    fi

}

function checkGroups() {

   if cat /etc/group | grep nopasswdlogin; then
        if promptYN "nopasswdlogin group found, would  you like to remove?"; then
            delgroup nopasswdlogin
        fi
    fi

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
        sudo chown -c root:root $i
        sudo chmod -c 644 $i
    fi
done

for i in "${SIXFORTY[@]}"; do
    if test -e "$i"; then
        sudo chown -c root:root $i
        sudo chmod -c 640  $i
    fi
done

for i in "${SIXHUNDRED[@]}"; do
    if test -e "$i"; then
        sudo chown -c root:root $i
        sudo chmod -c 600 $i
    fi
done

for i in "${SEVENHUNDRED[@]}"; do
    if test -e "$i"; then
        sudo chown -c root:root $i
        sudo chmod -c 700 $i
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
            echo "infected files will be moved to ~/cyberkit/clamscanresults"
            cont
            clamscan -r --move=clamscanresults /
        fi
    fi
    if promptYN "check clamscan results?"; then
        ls -lA clamscanresults/
        if promptYN "empty directory?"; then
            sudo rm clamscanresults/*
            sudo rm -r clamscanresults/*
        fi
    fi
    if promptYN "check for rootkits?"; then
        sudo apt install chkrootkit -yy
        cont
        clear
        chkrootkit
        clear
        echo "showing deleted entries:"
        chklastlog
    fi
}

function auditPolicy() {
    clear
    # install auditd
    sudo apt install auditd audispd-plugins -y

    # enable auditd
    sudo systemctl --now enable auditd

    #/etc/default/grub audit=1 
    compareFile /default/grub grub

    update-grub

}

function usbStorage() {
    clear
    if promptYN "disable external usb devices?"; then
        compareFile modprobe.d/blacklist.conf blacklist.conf
    fi

}

function fixApt() {
    sudo apt update
    echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
    echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
    if promptYN "System is Ubuntu (Y); System is Debian (N)"; then
        sudo add-apt-repository main
        sudo add-apt-repository universe
        sudo add-apt-repository restricted
        sudo add-apt-repository multiverse
        compareFile apt/sources.list sources.list
    else
        compareFile apt/sources.list debian_sources.list
    fi

}

function enableServices() {
    while promptYN "add another critical service?"; do
        clear
        echo "be sure to check config files for any of the following services"
        read -p "critical service: " service
        read -p "critical package: " package
        apt update
        apt install $package
        systemctl --now enable $service
    done
}

function checkSysctlConfs() {
    compareFile sysctl.conf sysctl.conf
    for filename in /etc/sysctl.d/*.conf; do
        clear
        filename=${filename##*/}
        compareFile sysctl.d/$filename sysctl.d/$filename
    done
    service procps restart
    sudo sysctl --system
}

function secureFirefox() {
    echo "setting preferences..."
    for destination in /home/*/.mozilla/firefox/*/; do
        cp -v configs/firefox/user.js $destination;
    done
    echo "select firefox from the list of available default browsers"
    sudo update-alternatives --config x-www-browser
    echo "check gui for additional preferences"
}

function fileDestroyer() {
    read -p "enter the path to the file you want to delete: " path
    FILEPATH=$path
    while [[ $FILEPATH != "" ]]; do
        echo "removing chattr attributes on $FILEPATH"
        chattr -ia $FILEPATH
        FILEPATH=$(echo $FILEPATH | rev | cut -d'/' -f2- | rev)
    done
    if promptYN -n "are you sure you would like to delete $path?"; then
        sudo rm -rf $path
    fi
}

function installDebianCIS() {
    git clone https://github.com/ovh/debian-cis.git && cd debian-cis
    cp debian/default /etc/default/cis-hardening
    sed -i "s#CIS_LIB_DIR=.*#CIS_LIB_DIR='$(pwd)'/lib#" /etc/default/cis-hardening
    sed -i "s#CIS_CHECKS_DIR=.*#CIS_CHECKS_DIR='$(pwd)'/bin/hardening#" /etc/default/cis-hardening
    sed -i "s#CIS_CONF_DIR=.*#CIS_CONF_DIR='$(pwd)'/etc#" /etc/default/cis-hardening
    sed -i "s#CIS_TMP_DIR=.*#CIS_TMP_DIR='$(pwd)'/tmp#" /etc/default/cis-hardening
    ./bin/hardening/1.1.1.1_disable_freevxfs.sh --audit
}

clear

echo "########## Welcome to J2K05's CyberKit Script ##########"
echo ""
echo "1. ENSURE THIS SCRIPT IS RUN AS ROOT"
echo "2. RUN SCRIPT IN ~/cyberkit"
echo "3. COMPLETE FORENSICS QUESTIONS FIRST"
echo "4. SET FIREFOX PREFERENCES THROUGH GUI"
echo ""

if [ ! -d passwords/ ]; then
    sudo mkdir passwords
fi
if [ ! -d backups/ ]; then
    sudo mkdir backups
    sudo mkdir backups/sysctl.d
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
        echo "" 
        echo "1. update all packages"
        echo "2. enable automatic software updates"
        echo ""
        echo "3. check users and groups"
        echo "4. secure sudo" #https://phpraxis.wordpress.com/2016/09/27/enable-sudo-without-password-in-ubuntudebian/
        echo "5. set password policy"
        echo ""
        echo "6. enable and configure ufw"
        echo "7. secure ssh"
        echo "8. disable IPv4 forwarding" #https://linuxconfig.org/how-to-turn-on-off-ip-forwarding-in-linux
        echo ""
        echo "9. search home directory for unwanted files"
        echo "10. check software"
        echo "11. check services"
        echo "12. set file permissions"
        echo ""
        echo "13. check for malware"
        echo ""
        echo "14. audit policy"
        echo "15. disable usb storage"
        echo ""
        echo "16. check sysctl.d"
        echo "17. secure firefox"
        echo ""
        echo "18. file destroyer" # removes chattr attributes on all parent directories
        echo ""
        echo "19. check software [ALL]"
        echo "20. install Debian CIS"

        read -p "enter section number: " secnum
}

selector
case $secnum in
1) upgradeAll;;
2) softwareUpdates;;
3) checkUsers;;
4) secureSudo;; 
5) passwordPolicy;;
6) ufwEnable;;
7) secureSSH;;
8) disableIPv4;;
9) searchHome;;
10) checkSoftware;; 
11) checkServices;;
12) filePermissions;;
13) checkMalware;;
14) auditPolicy;;
15) usbStorage;;
16) checkSysctlConfs;;
17) secureFirefox;;
18) fileDestroyer;;
19) checkSoftwareBeta;;
20) installDebianCIS;;
esac

exit