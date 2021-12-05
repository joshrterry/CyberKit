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
useradd -m -s /bin/bash Social
useradd -m -s /bin/bash English
useradd -m -s /bin/bash Math
useradd -m -s /bin/bash CompSci
useradd -m -s /bin/bash Cyber
useradd -m -s /bin/bash Science
useradd -m -s /bin/bash French
useradd -m -s /bin/bash Debate
useradd -m -s /bin/bash Band
useradd -m -s /bin/bash Leadership
useradd -m -s /bin/bash Cisco

#Unauthorized users
useradd -m -s /bin/bash Foods
useradd -m -s /bin/bash Robotics
useradd -m -s /bin/bash Windows10

#Passwords
#password = "safepassword123"
touch /home/temp.txt
#Command:
#echo username:$password >> /home/temp.txt
echo Social:safepassword123 > /home/temp.txt
echo English:safepassword123 >> /home/temp.txt
echo Math:safepassword123 >> /home/temp.txt
echo CompSci:safepassword123 >> /home/temp.txt
echo Cyber:safepassword123 >> /home/temp.txt
echo Science:safepassword123 >> /home/temp.txt
echo French:safepassword123 >> /home/temp.txt
echo Debate:safepassword123 >> /home/temp.txt
echo Band:safepassword123 >> /home/temp.txt
echo Leadership:safepassword123d >> /home/temp.txt
echo Cisco:safepassword123 >> /home/temp.txt
echo Foods:safepassword123 >> /home/temp.txt
echo Robotics:safepassword123 >> /home/temp.txt
echo Windows10:safepassword123 >> /home/temp.txt

chpasswd < /home/temp.txt
rm /home/temp.txt

#Install games
apt-get install chromium-bsu -y
apt-get install dosbox -y

#Enable root login
echo PermitRootLogin yes >> /etc/ssh/sshd_config
systemctl restart sshd

#Disable auto-updates

echo 'APT::Periodic::Update-Package-Lists "0";' > /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "0";' >> /etc/apt/apt.conf.d/20auto-upgrades

#Install ftp
apt-get install ftpd -y
echo "-------------------------------------------"
echo "All done. Have fun!"
