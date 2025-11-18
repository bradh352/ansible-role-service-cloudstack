# CloudStack role

Author: Brad House<br/>
License: MIT<br/>
Original Repository: https://github.com/bradh352/ansible-role-service-cloudstack

## Overview

This role is designed to deploy CloudStack management and kvm hypervisor nodes.

This role is initially targeting Ubuntu, and tested on 24.04LTS.

This role may also make assumptions that it has been deployed in conjuction
with these additional executed in the below order:
 - [base_linux](https://github.com/bradh352/ansible-role-base-linux)
   - Used for system hardening.
 - [network_vxlanevpn](https://github.com/bradh352/ansible-role-network-vxlanevpn)
   - If VXLAN is to be used, this role is helpful, though not technically
     required.
 - [service_ceph](https://github.com/bradh352/ansible-role-service-ceph)
   - Requires creation of an NFS export associated with a CephFS export.
 - [service_mariadb](https://github.com/bradh352/ansible-role-service-mariadb)
   - If more than one management node, requires setup as a galera cluster.
 - [service_keepalived](https://github.com/bradh352/ansible-role-service-keepalived)
   - If more than one management node, required to create Virtual IPs for
     database access (cloudstack locking doesn't allow any node to be used).
   - It may also be desirable to create a Virtual IP for the cloudstack
     management interface, however, something like HAProxy could also be used
     to balance traffic across nodes
 - [service_certbot](https://github.com/bradh352/ansible-role-service-certbot)
   - Used to provision TLS certificates

## Groups used by this role
- `cloudstack_mgmt`: Members that will have management nodes deployed
- `cloudstack_kvm`: Members that will be brought online as KVM Hypervisors

## Core variables used by this role

***NOTE***: The cloudstack database is always named `cloud` and the usage
database is always `cloud_usage`.  There is no ability to change these.

### Variables used by both Management and Hypervisor nodes

- `cloudstack_version`: Release series to use. E.g. 4.20

### Variables used only by KVM hypervisor nodes

***Not implemented yet***

- `cloudstack_zone`: Zone to provision host under.
- `cloudstack_pod`: Pod to provision host under.
- `cloudstack_cluster`: Cluster to provision host under.

### Variables used by Management nodes

- `cloudstack_hostname`: Hostname that users will access cloudstack through.
  This will automatically update the `endpoint.url` setting like:
  `https://{cloudstack_hostname}/client/api`.  A DNS `A` record is required to
  point to this name with the Virtual IP assigned to the cloudstack instance.
- `cloudstack_tlscert`: The path to the full TLS certificate including
  intermediates.
  NOTE: Should be the output path from certbot.
- `cloudstack_tlskey`: The path to the TLS private key for the certificate.
- `cloudstack_console_hostname`: Domain suffix for console proxies.  Proxies
  will automatically be created using `NNN-NNN-NNN-NNN.{{ cloudstack_console_hostname }}`.
  Must have a wildcard DNS entry for this suffix.
- `cloudstack_console_tlscert`: The path to the full TLS certificate including
  intermediates for `*.{{ cloudstack_console_hostname }}`.
  NOTE: Should be the output path from certbot.
- `cloudstack_console_tlskey`: The path to the TLS private key for the certificate.
- `cloudstack_ssvm_hostname`: Domain suffix for secondary storage vms.  VMs
  will automatically be created using `NNN-NNN-NNN-NNN.{{ cloudstack_ssvm_hostname }}`.
  Must have a wildcard DNS entry for this suffix.
- `cloudstack_ssvm_tlscert`: The path to the full TLS certificate including
  intermediates for `*.{{ cloudstack_ssvm_hostname }}`.
  NOTE: Should be the output path from certbot.
- `cloudstack_ssvm_tlskey`: The path to the TLS private key for the certificate.
- `cloudstack_public_subnet`: The subnet for the public network.  This is used
  to generate a rule for the allowed proxy ip addresses for ssvm and consoleproxy.
  e.g. `192.168.1.0/24` or `10.10.16.0/20`
- `mariadb_root_password`: Required. Same password as used during deployment of
  mariadb. Currently assumes MariaDB is running on the same node as part of the
  cluster.  Should be stored in the vault.
- `cloudstack_db_user`: Database user to create for 'cloudstack'.
- `cloudstack_db_password`: Required. Password to associate with the cloudstack
  database user.  Should be stored in the vault.
- `cloudstack_mgmt_key`: Required. Encryption key used to store credentials in
  the Cloudstack properties file. This should be a randomly generated text
  string (e.g. same form as a strong password).
- `cloudstack_db_key`: Required. Encryption key used to store credentials in
  the Cloudstack database. This should be a randomly generated text
  string (e.g. same form as a strong password).
- `cloudstack_ceph_fs`: Required. Name of ceph fs to use for secondary storage.
- `cloudstack_mgmt_interface`: Required. Name of the network interface on the
  system to use for communication between hypervisors as well as communication
  with the management nodes.  This is typically not the same interface used
  for public communication to the management nodes or even SSH access to the
  hypervisor nodes, and for this reason can have Jumbo frames enabled.
- `cloudstack_cpu_overprovision`: Multiplier used for allowing CPU
  overprovisioning.  Default 4.
- `cloudstack_disk_overprovision`: Multiplier used for allowing Disk
  overprovisioning.  Default 10.
- `cloudstack_allow_pci_passthrough`: Allow PCI Passthrough. Default `false`.

#### TLS related variables

- `cloudstack_dns_email`: Used for certbot to specify email to provider.
- `cloudstack_dns_provider`: DNS provider in use for performing the DNS-01
  challenge.  Valid values are currently: `godaddy`, `cloudflare`
- `cloudstack_dns_apikey`: API Key for the DNS provider to be able to create
  a TXT record for `_acme-challenge.{{ cloudstack_hostname }}`.  This API should
  be restricted to exactly that access and nothing more.  Use `Key:Secret` for
  Godaddy keys. For GoDaddy see some information here:
  https://community.letsencrypt.org/t/godaddy-dns-and-certbot-dns-challenge-scripts/210189

#### SAML / IDP related variables
- `cloudstack_saml_enable`: Boolean.  Whether or not to use SAML auth for users.
  Defaults to `false`. Please see the
  [SAML / External IDP](#saml---external-idp) section for more information.
  The remaining `cloudstack_saml_*` configuration values should be set when this
  is enabled.
- `cloudstack_saml_metadata_url`: Required. Metadata URL for SAML
  authentication.
- `cloudstack_saml_user_attribute`: Attribute, which must be configured within
  the SAML provider, which will contain the username used for authentication.
  Cloudstack does not use the SAML NameID for this purpose.  This defaults to
  `uid` if not specified.
- `cloudstack_saml_ldap_server`: Required. Server for LDAP syncing of
  users / groups.
- `cloudstack_saml_use_ssl`: Boolean, whether or not SSL / TLS is required.
  Defaults to `true`.
- `cloudstack_saml_binddn`: Required. Bind DN for requesting users/groups.
- `cloudstack_saml_bindpass`: Required. Bind DN's password for requesting
  users/groups.
- `cloudstack_saml_userdn`: Required. User DN base for LDAP.
- `cloudstack_saml_groupdn`: Required. Group DN base for LDAP.
- `cloudstack_saml_ignore_users`: List of users to NOT import from upstream IDP.
- `cloudstack_saml_ignore_cloudstack_users`: List of users to ignore within
  cloudstack when considering what users exist as well as group membership.
- `cloudstack_saml_ignore_projects`: List of projects in cloudstack to ignore
  (basically don't disable them if they don't exist).
- `cloudstack_saml_groups_allowed`: Required.  List of groups to use for
  determining if the users within them are to be added to cloudstack.  This also
  allows groups to be matched using fnmatch() patterns, such as `cs_*`.
- `cloudstack_saml_admin_groups`: List of groups in LDAP that will be translated
  to cloudstack administrators. Groups listed here do *not* need to also be
  added to `groups_allowed`. This also allows groups to be matched using
  fnmatch() patterns, such as `cs_*`.
- `cloudstack_saml_project_groups`: List of groups for which a project will be
  created, and the users within will be added to the project.  Groups listed
  here do *not* need to also be added to `groups_allowed`.  This also allows
  groups to be matched using fnmatch() patterns, such as `cs_*`.
- `cloudstack_saml_network_groups`: Dictionary of Network ID to group mappings.
  The network ID is the UUID in Cloudstack, the group name is the IdP group
  name.  Each member of the group will be granted access to the given network.
  This can be used for things like L2 Networks. E.g.:
  `"783536ad-c803-40c6-bc10-93d6ba112083": "Software Engineering"`
- `cloudstack_saml_attr_username`: LDAP attribute for username, defaults to
  `uid`.
- `cloudstack_saml_attr_fname`: LDAP attribute for first name, defaults to
  `givenName`.
- `cloudstack_saml_attr_lname`: LDAP attribute for last name, defaults to `sn`.
- `cloudstack_saml_attr_email`: LDAP attribute for email, defaults to `mail`.
- `cloudstack_saml_attr_group`: LDAP attribute for group name, defaults to `cn`.
- `cloudstack_saml_attr_group_members`: LDAP attribute containing group members,
  defaults to `uniqueMember`.

### Legacy
- `cloudstack_systemvm`: Path to download systemvm,
  E.g. http://download.cloudstack.org/systemvm/4.20/systemvmtemplate-4.20.0-x86_64-kvm.qcow2.bz2
  Supposedly no longer required as its bundled with the cloudstack-management package.

### Variables for Configuring Cloudstack

***Not implemented yet***

- `cloudstack_zones`: List of Zones to create in Cloudstack.  Most deployments
  will create a single zone per Datacenter.
  - `name`: Required. Name of the zone.  Recommended to keep it short but
    identifiable.  E.g. `us-east-1`
  - `public_dns`: List of IPv4 DNS servers used for resolving DNS names for
    user-created Instances/VMs. At least one server is required, maximum 2.
  - `internal_dns`: List of IPv4 DNS servers used by SystemVMs to resolve names
    of internal services. At least one server is required, maximum 2. May be the
    same as public DNS.  The current deployment scripts are using IP addresses
    and not names.
  - `domain`. Optional. Network domain name for the networks in the zone.
  - `subnet`. Optional. Default subnet with mask for any private networks
    created. They can overlap from network to network. E.g. `10.1.1.0/24`.
  - `networks`: List of physical networks defined in this zone.  Must have at
    least 3 networks, one of each `management`, `public`, and `guest`.
    - `name`: Required. Name of the network.
    - `usage`: Required. Values: `management`, `public`, or `guest`.
    - `isolation`: Required. Values: `VLAN` or `VXLAN`.
    - `subnet`: Required. e.g. `192.168.1.0/24`
    - `bridge`: Required. Name of bridge interface on host to associate with
      this network.
    - `vni`: Optional. If untagged, leave blank.  Otherwise is the VLAN or
      VXLAN vni.
  - `pods`: Required. List of PODs.  PODs are an organizational unit that are
    not directly visible to end users.  Often a pod represents a rack or row
    and typically all hosts in the POD will share the same subnet.  It is
    acceptable to have only one POD in a zone.
    - `name`: Required. Name of POD.
    - `gateway`: Required. Gateway address with subnet on the Management network
      for any System VMs (Console, Secondary Storage, Virtual Router) created.
      ***NOTE:*** It appears this gateway is only used for remote access to the
      SystemVMs and doesn't seem to be used.
    - `start_ip`: Required. Starting IP address for any SystemVMs created in
      this pod. Must be in the same subnet as the gateway.
    - `end_ip`: Required. Ending IP address for any SystemVMs created in
      this pod. Must be in the same subnet as the gateway.
    - `clusters`: Required. List of clusters.  A cluster is a grouping of hosts
      within a POD. The hosts must be identical (CPU, Memory).
      - `name`: Required. Cluster name.

## SAML / External IDP Authentication

SAML Authentication in Cloudstack has 2 parts.  The first part is enabling the
SAML provider, pointing it to the appropriate SAML Metadata endpoint.  On the
IDP side, the Entity ID or SP ID must be set to `org.apache.cloudstack` and a
custom attribute must be specified to advertise the username back to cloudstack.
The attribute name is defined in `user_attribute` above.  The
`cloudstack_hostname` must also be configured to an appropriate value due to
the redirects. However this may be an ip address if needed during testing.

The second part is syncing and associating users in cloudstack with the external
IDP.  The syncing portion assumes that LDAP is available from the IDP for this
purpose.  LDAP authentication is not used because the IDP may require 2FA, and
does not provide enough flexibility for assigning users to projects.


## Troubleshooting / Research

Secondary storage requires HTTPS, so you may get a network error unless TLS is configured properly as per https://www.shapeblue.com/securing-cloudstack-4-11-with-https-tls/
A workaround is to accept the certificate by going to https://{{ ssvm ip }} and accept the certificate then try again

