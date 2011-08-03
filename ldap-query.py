#!/usr/bin/env python

# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is the ldap-query for SSH keys.
#
# The Initial Developer of the Original Code is
# Mozilla Corporation
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
# jdow@mozilla.com
# gdestuynder@mozilla.com
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#

import sys
import ldap
import base64, hashlib
import traceback

from ldapconf import *

def main():

    try:
        kw = sys.argv[1]
    except IndexError:
        print ("Need one argument, email-username or ssh fingerprint")
        sys.exit (1)

    try:
        l = ldap.initialize(ldapUri)
        l.simple_bind_s(bindDn, ldapPass)
        my_search(l, kw)
    except ldap.LDAPError, error_message:
        print ("Couldn't Connect. %s " % error_message)


def my_search(l, kw):
    scope = ldap.SCOPE_SUBTREE
    if kw.find('@') != -1:
        filterk = 'mail='+kw
        mode=1
    elif kw.find(':') != -1:
	filterk = "cn=*"
        mode = 2
    else:
        print ("Nothing that looks like an email or an ssh fingerprint, well, goodbye!")
        sys.exit (2)
    retrieve_attributes = ['sshPublicKey']
    count = 0
    result_set = []
    timeout = 0

    try:
        result_id = l.search(base, scope, filterk, retrieve_attributes)
        while 1:
            result_type, result_data = l.result(result_id, timeout)
            if (result_data == []):
                break
            elif result_type == ldap.RES_SEARCH_ENTRY:
                result_set.append(result_data)

        if len(result_set) == 0:
            print ("No Results.")
            return 

        for i in range(len(result_set)):
            for entry in result_set[i]:                 
                try:
                    key = entry[1]['sshPublicKey']
                    mail = entry[0]
                    count = count + 1
                    for pubkey in key:
			#Fix for broken keys
                        pubkey = pubkey.replace('ssh-rsa\r\n', 'ssh-rsa ') #
                        pubkey = pubkey.replace('ssh-dss\r\n', 'ssh-dss ')
                        pubkey = pubkey.replace('ssh-ecdsa\r\n', 'ssh-ecdsa ')
                        pubkey = pubkey.replace('=\r\n', '= ')
                        pubkey = pubkey.replace('\r\n', '')
                        if mode == 1:
                            print (pubkey)
                        else:
                            fp = key2fingerprint(pubkey)
                            if fp == kw:
                                print (mail)
                                print (fp)
                except:
                    pass

    except ldap.LDAPError, error_message:
        traceback.print_exc()
        print (error_message)

def key2fingerprint(key):
	"""Translate an ssh key to it's md5 fingerprint"""
	key = base64.b64decode(key.strip().split(' ')[1])
	fp = hashlib.md5(key).hexdigest()
	return ':'.join(a+b for a,b in zip(fp[::2], fp[1::2]))

if __name__=='__main__':
    main()
