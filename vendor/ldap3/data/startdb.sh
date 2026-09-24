#!/bin/sh

slapd -h "ldapi://ldapi ldap://${LDAP3_EXAMPLE_SERVER:-localhost}:2389 ldaps://${LDAP3_EXAMPLE_SERVER:-localhost}:2636" -F config "$@"
