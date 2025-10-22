# Created by Griff for OSSTMM testing of an AD server
# Eventually will map to controls

from ldap3 import Server, Connection, ALL, NTLM, ANONYMOUS, ALL_ATTRIBUTES
import dns.resolver

# Configuration
domain_controller = 'your.domain.controller'
domain = 'yourdomain.local'

# LDAP visibility check: Test LDAP connectivity
def check_ldap():
    server = Server(domain_controller, get_info=ALL)
    try:
        conn = Connection(server)
        if conn.bind():
            print("LDAP service is reachable")
            conn.unbind()
        else:
            print("LDAP service not reachable or bind failed")
    except Exception as e:
        print(f"LDAP connection error: {e}")

# Anonymous bind check: Test if anonymous bind allowed (visibility risk)
def anonymous_bind_check():
    server = Server(domain_controller)
    try:
        conn = Connection(server, authentication=ANONYMOUS)
        if conn.bind():
            print("Anonymous LDAP bind successful - visibility risk")
            conn.unbind()
        else:
            print("Anonymous LDAP bind failed")
    except Exception as e:
        print(f"Anonymous LDAP error: {e}")

# Enumerate users (basic visibility check)
def enumerate_users():
    server = Server(domain_controller)
    try:
        # No credentials given; will likely fail if anon bind disabled
        conn = Connection(server, authentication=ANONYMOUS, read_only=True)
        if not conn.bind():
            print("Cannot enumerate users - access denied")
            return
        conn.search(search_base='dc=yourdomain,dc=local',
                    search_filter='(objectClass=user)',
                    attributes=['sAMAccountName'])
        print("Users found:")
        for entry in conn.entries:
            print(entry.sAMAccountName)
        conn.unbind()
    except Exception as e:
        print(f"User enumeration error: {e}")

# DNS SRV record check to find AD LDAP service records (visibility)
def check_dns_srv_records():
    try:
        answers = dns.resolver.resolve(f'_ldap._tcp.{domain}', 'SRV')
        print(f"DNS SRV records for _ldap._tcp.{domain}:")
        for rdata in answers:
            print(f"Target: {rdata.target}, Port: {rdata.port}")
    except Exception as e:
        print(f"DNS SRV record error: {e}")

if __name__ == '__main__':
    check_ldap()
    anonymous_bind_check()
    enumerate_users()
    check_dns_srv_records()
