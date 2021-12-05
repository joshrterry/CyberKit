#!/bin/bash/
#This script sets up an Ubuntu machine for practice for Cyberpatriots.
#Made by Rohan Bhargava
$input
echo "Hello! This script sets up an Ubuntu machine for practice for Cyberpatriots. Made by Rohan Bhargava. Run this as ROOT."
echo "Press enter when you are ready!"
read input

#install hacking tools
apt-get install nmap -y
apt-get install wireshark -y
apt-get install telnet -y
apt-get install themole -y
apt-get install goldeneye -y


#Adding users
#Command:
#useradd -m -s /bin/bash username
useradd -m -s /bin/bash social
useradd -m -s /bin/bash english
useradd -m -s /bin/bash math
useradd -m -s /bin/bash compsci
useradd -m -s /bin/bash cyber
useradd -m -s /bin/bash science
useradd -m -s /bin/bash french
useradd -m -s /bin/bash debate
useradd -m -s /bin/bash band
useradd -m -s /bin/bash leadership
useradd -m -s /bin/bash cisco

#Unauthorized users
useradd -m -s /bin/bash foods
useradd -m -s /bin/bash robotics
useradd -m -s /bin/bash windows

#Passwords
#password = "safepassword123"
touch /home/temp.txt
#Command:
#echo username:$password >> /home/temp.txt
echo social:safepassword123 > /home/temp.txt
echo english:safepassword123 >> /home/temp.txt
echo math:safepassword123 >> /home/temp.txt
echo compSci:safepassword123 >> /home/temp.txt
echo cyber:safepassword123 >> /home/temp.txt
echo science:safepassword123 >> /home/temp.txt
echo french:safepassword123 >> /home/temp.txt
echo debate:safepassword123 >> /home/temp.txt
echo band:safepassword123 >> /home/temp.txt
echo leadership:safepassword123d >> /home/temp.txt
echo cisco:safepassword123 >> /home/temp.txt
echo foods:safepassword123 >> /home/temp.txt
echo robotics:safepassword123 >> /home/temp.txt
echo windows:safepassword123 >> /home/temp.txt

/home/temp.txt | chpasswd
rm /home/temp.txt

#Install games
apt-get install chromium-bsu -y
apt-get install dosbox -y

#Enable root login
echo PermitRootLogin yes >> /etc/ssh/sshd_config
systemctl restart sshd

#Disable auto-updates

echo APT::Periodic::Update-Package-Lists "0"; > /etc/apt/apt.conf.d/20auto-upgrades
echo APT::Periodic::Unattended-Upgrade "0"; >> /etc/apt/apt.conf.d/20auto-upgrades

#Install ftp
apt-get install ftpd -y
echo "-------------------------------------------"
echo "All done. Have fun!"
