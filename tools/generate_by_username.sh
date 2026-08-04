#!/bin/bash

usage(){
    echo "bash $(basename $0) <username>"
}

[ -z $1 ] && usage && exit 1

username=$1
muban="muban.key"

cat $muban|sed 's/%user%/'$username'/g'
