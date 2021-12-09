#!/bin/bash

read -p "exemplar file: " exemplar
read -p "original file: " original


echo "displaying differences in $original file"
diff $exemplar $original
if promptYN -n "overwrite $original?"; then
    echo "backing up to cypat/backups..."
    cp $original backups/$original
    echo "overwriting $original..."
    cat $exemplar > $original
fi

