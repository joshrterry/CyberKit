#!/bin/bash
# small script for comparing config files and writing to them with exemplars

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

function filecompare() {
    echo "displaying differences in $original file"
    diff $exemplar $original
    if promptYN -n "overwrite $original?"; then
        echo "backing up to cypat/backups..."
        cp $original backups/$original
        echo "overwriting $original..."
        cat $exemplar > $original
    fi
}

read -p "exemplar file: " exemplar
read -p "original file: " original
filecompare

exit