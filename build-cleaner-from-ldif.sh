#!/bin/bash
# create an ldapmodify script to delete dns listed in the source ldif
grep "dn:" "$1" | while read -r i; do echo "$i"; echo "changetype: delete"; echo ""; done
