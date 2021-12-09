#!/bin/bash
# small script for comparing files and writing to files with exemplars

function promptYN() {
    prompt="$1 [Y/n] "
    if [[ "$1" == "-n" ]]; then
        prompt="$2 [y/N] "
    fi

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