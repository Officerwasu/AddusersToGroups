"""
Author: @JulioUrena (modified for PTH support by @5epi0l and Kerberos Support by @Officerwasu)
License: GPL-3.0 license
"""

import argparse
import sys
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD, GSSAPI, SASL

# Parse arguments
parser = argparse.ArgumentParser(description='Add a user to an Active Directory group using LDAP.')
parser.add_argument('-d', '--domain', required=True, help='The domain name of the Active Directory server.')
parser.add_argument('-g', '--group', required=True, help='The name of the group to add the user to.')
parser.add_argument('-a', '--adduser', required=True, help='The username of the user to add.')
parser.add_argument('-u', '--user', required=True, help='The username with AddMember privilege.')
parser.add_argument('-p', '--password', help='Password of the user (optional if --hash is provided).')
parser.add_argument('--hash', help='NTLM hash in the format LMHASH:NTHASH (LMHASH usually set to aad3b435b51404eeaad3b435b51404ee).')
parser.add_argument('-k', '--kerberos', action='store_true', help='Use Kerberos authentication. (Uses KRB5CCNAME environment variable)')

args = parser.parse_args()

# Extract arguments
domain_name = args.domain
group_name = args.group
user_name = args.adduser
ad_username = args.user
ad_password = args.password
ad_hash = args.hash
use_kerberos = args.kerberos

# Validate authentication
if not ad_password and not ad_hash and not use_kerberos:
    print('[-] Error: Provide either --password, --hash, or --kerberos for authentication.')
    sys.exit(1)

# Construct search base
search_base = 'dc=' + ',dc='.join(domain_name.split('.'))

# Prepare connection
server = Server(domain_name, get_info=ALL)

if use_kerberos:
    conn = Connection(
        server,
        authentication=SASL,
        sasl_mechanism='GSSAPI'
    )

elif ad_hash:
    conn = Connection(
        server,
        user=f'{domain_name}\\{ad_username}',
        authentication = NTLM,
        password_field = ad_hash
    )

else:
    conn = Connection(
        server,
        user=f'{domain_name}\\{ad_username}',        
        authentication = NTLM,
        password_field = ad_password
    )


# Bind to AD
if conn.bind():
    print('[+] Connected to Active Directory successfully.')
else:
    print('[-] Error: Failed to bind to Active Directory server.')
    sys.exit(1)

# Search for group
conn.search(
    search_base=search_base,
    search_filter=f'(&(objectClass=group)(cn={group_name}))',
    attributes=['member']
)

if not conn.entries:
    print('[-] Error: Group not found.')
    sys.exit(1)

group_dn = conn.entries[0].entry_dn
members = conn.entries[0].member.values

# Search for user
conn.search(
    search_base=search_base,
    search_filter=f'(&(objectClass=user)(sAMAccountName={user_name}))',
    attributes=['distinguishedName']
)

if not conn.entries:
    print('[-] Error: User not found.')
    sys.exit(1)

user_dn = conn.entries[0].distinguishedName.value

# Check membership
if user_dn in members:
    print('[+] User is already a member of the group.')
else:
    if conn.modify(
        dn=group_dn,
        changes={'member': [(MODIFY_ADD, [user_dn])]}
    ):
        print('[+] User added to group successfully.')
    else:
        print('[-] Error adding user to group.')
