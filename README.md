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
     to balance traffic across nodes.

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

- `cloudstack_systemvm`: Required. Path to download systemvm,
  E.g. http://download.cloudstack.org/systemvm/4.20/systemvmtemplate-4.20.0-x86_64-kvm.qcow2.bz2
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

## Troubleshooting / Research

Secondary storage requires HTTPS, so you may get a network error unless TLS is configured properly as per https://www.shapeblue.com/securing-cloudstack-4-11-with-https-tls/
A workaround is to accept the certificate by going to https://{{ ssvm ip }} and accept the certificate then try again

