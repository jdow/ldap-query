#!/usr/bin/env python

import sys
import ldap

from ldapconf import *

def main():

    if (len(sys.argv) > 2):
        print "Please only specify one argument"
        exit()
    elif (len(sys.argv) < 2):
        print "Please specify an ldap username"
        exit()
    else:
        keyword = sys.argv[1]

    try:
        l = ldap.initialize(ldapUri)
        l.simple_bind_s(bindDn, ldapPass)
        my_search(l, keyword)
    except ldap.LDAPError, error_message:
        print "Couldn't Connect. %s " % error_message


def my_search(l, keyword):
    scope = ldap.SCOPE_SUBTREE
    filter = rdn + keyword
    retrieve_attributes = ['sshPublicKey']
    count = 0
    result_set = []
    timeout = 0

    try:
        result_id = l.search(base, scope, filter, retrieve_attributes)
        while 1:
            result_type, result_data = l.result(result_id, timeout)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
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
