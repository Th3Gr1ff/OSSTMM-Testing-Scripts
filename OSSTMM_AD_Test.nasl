# Created by Griff @ ISECOM, add this to your Nessus NASL scripts
# Replace relevant information such as domain/user/etc, Ideally use a readonly domain account for such activity.
# You can manually map the OSSTMM controls to the findings, I may add them later but will probably just wait until OSSTMM v4 which is in the works now.

include("ldap_func.nasl");
include("compat.inc");

port = 389;

if (!port_available(port)) {
    exit(0);
}

ldap_host = get_kb_item("HOST_IP");
username = "readonlyuser@yourdomain.local";
password = "readonlypassword";

search_base = "DC=yourdomain,DC=local";

function security_warning(p) {
    security_message = "OSSTMM AD LDAP visibility/access issue detected on port " + p;
    security_alarm(security_message, WSN, AVAIL, 0, 0);
}

function ldap_bind_and_search(base, filter, attrs) {
    bind_dn = username; // Use UPN format for binding
    bind_result = ldap_simple_bind(ldap_host, port, bind_dn, password);

    if (bind_result != 0) {
        display("LDAP bind failed for user " + bind_dn + "\n");
        return -1;
    }

    search_result = ldap_search(ldap_host, port, bind_dn, password, base, filter, attrs);

    if (search_result != 0) {
        display("LDAP search failed for filter: " + filter + "\n");
        return -1;
    }

    entries_count = ldap_num_entries();
    display("Found " + entries_count + " entries for filter: " + filter + "\n");

    for (i = 0; i < entries_count; i++) {
        entry = ldap_get_entry(i);
        display("Entry " + (i+1) + ":\n");
        split_attrs = split(attrs, ",");
        foreach (a in split_attrs) {
            trimmed_attr = trim(a);
            val = ldap_get_values(entry, trimmed_attr);
            if (typeof(val) == "array") {
                foreach (v in val) {
                    display("  " + trimmed_attr + ": " + v + "\n");
                }
            } else {
                display("  " + trimmed_attr + ": " + val + "\n");
            }
        }
        display("\n");
    }

    ldap_unbind();
    return 0;
}

# Main script starts here

status = ldap_connect(ldap_host, port);

if (status != 0) {
    display("LDAP port " + port + " not reachable on " + ldap_host + "\n");
    exit(0);
}

security_warning(port);
display("LDAP port " + port + " is open on " + ldap_host + "\n");

# Anonymous bind test
anon_bind = ldap_simple_bind(ldap_host, port, "", "");
if (anon_bind == 0) {
    security_warning(port);
    display("Anonymous LDAP bind successful - visibility risk\n");
} else {
    display("Anonymous LDAP bind failed\n");
}

# Bind using readonly account and enumerate AD objects

# Domain Controllers
ldap_bind_and_search(search_base, "(objectClass=domainController)", "dNSHostName");

# Trust Relationships
ldap_bind_and_search(search_base, "(objectClass=trustedDomain)", "cn,trustDirection,trustType,trustAttributes");

# Delegation Settings - Computers with delegation rights
ldap_bind_and_search(search_base, "(&(objectClass=computer)(msDS-AllowedToDelegateTo=*))", "cn,msDS-AllowedToDelegateTo");

# Delegation Settings - Users with delegation flag
ldap_bind_and_search(search_base, "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))", "cn,userAccountControl");

# Users with attributes
ldap_bind_and_search(search_base, "(objectClass=user)", "sAMAccountName,mail,memberOf");

# Groups with attributes
ldap_bind_and_search(search_base, "(objectClass=group)", "cn,member,groupType");

# Group Policy Objects (GPO)
gpo_base = "CN=Policies,CN=System," + search_base;
ldap_bind_and_search(gpo_base, "(objectClass=groupPolicyContainer)", "cn,displayName,gpLink,versionNumber");
