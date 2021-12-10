#!/bin/bash

touch admins.txt
touch standards.txt

read -p "paste all admins below:" >> admins.txt

read -p "paste all standard users below:" >> standards.txt

exit