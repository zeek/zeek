#! /usr/bin/env bash

set -e

if [ $# -ne 2 ]; then
    echo "usage: $0 <external repo path> <file to store commit in>"
    exit 1
fi

repo_dir=$1
hash_file=$2

repo_base=$(basename $repo_dir)
file_base=$(basename $hash_file)

if [ ! -d "$repo_dir" ]; then
    echo "External repo does not exist: $repo_dir"
    exit 1
fi

printf "Checking for '$repo_base' changes ..."

origin_hash=$(cd $repo_dir && git fetch origin && git rev-parse origin/master)
head_hash=$(cd $repo_dir && git rev-parse HEAD)
file_hash=$(cat $hash_file)

if [ "$file_hash" != "$head_hash" ]; then
    printf "\n"
    printf "\n"
    printf "  '$repo_base' pointer has changed:\n"

    line="    $file_base at $file_hash"
    len=${#line}

    printf "%${len}s\n" "$line"
    printf "%${len}s\n" "origin/master at $origin_hash"
    printf "%${len}s\n" "HEAD at $head_hash"
    printf "\n"
    printf "Update file '$file_base' to HEAD commit ? "

    read -p "[Y/n] " choice

    case "$choice" in
        n | N) echo "Skipped '$repo_base'" ;;
        *) echo $head_hash >$hash_file && git add $hash_file && echo "Updated '$file_base'" ;;
    esac
else
    echo " none"
fi
