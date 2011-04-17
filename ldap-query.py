#!/usr/bin/env python

# This is my first attempt at writing some python code
# Hopefully this will start looking better as I clean it up

import sys
import ldap

# Grab all the variables from ldapconf.py
from ldapconf import *

def main():

# Currently I only want one argument: the rdn of a user
# This will get changed in a new version soon
    if (len(sys.argv) > 2):
        print "Please only specify one argument"
        exit()
    elif (len(sys.argv) < 2):
        print "Please specify an ldap username"
        exit()
    else:
        keyword = sys.argv[1]

# Initialize the connection to the LDAP server
    try:
        l = ldap.initialize(ldapUri)
        l.simple_bind_s(bindDn, ldapPass)
        my_search(l, keyword)
    except ldap.LDAPError, error_message:
        print "Couldn't Connect. %s " % error_message


def my_search(l, keyword):
    scope = ldap.SCOPE_SUBTREE
    filter = rdn + keyword
# Right now, I just want the sshPublicKey attribute
    retrieve_attributes = ['sshPublicKey']
    count = 0
    result_set = []
    timeout = 0

# use the search method to grab the ssh key's of a given user
    try:
        result_id = l.search(base, scope, filter, retrieve_attributes)
        while 1:
            result_type, result_data = l.result(result_id, timeout)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)

# Step through the resulting tuple and grab all the keys
        if len(result_set) == 0:
            print "No Results."
            return 
        for i in range(len(result_set)):
            for entry in result_set[i]:                 
                try:
                    key= entry[1]['sshPublicKey']
                    count = count + 1
                    for pubkey in key:
# The following substitutions are a hack to work around "broken" keys in our ldap database
                        pubkey = pubkey.replace('ssh-rsa\r\n', 'ssh-rsa ') #
                        pubkey = pubkey.replace('ssh-dss\r\n', 'ssh-dss ')
                        pubkey = pubkey.replace('=\r\n', '= ')
                        pubkey = pubkey.replace('\r\n', '')
                        print pubkey
                except:
                    pass
    except ldap.LDAPError, error_message:
        print error_message

if __name__=='__main__':
    main()
