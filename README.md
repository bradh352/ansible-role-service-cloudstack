# CloudStack role

Author: Brad House<br/>
License: MIT<br/>
Original Repository: https://github.com/bradh352/ansible-scripts/tree/master/roles/service_ceph

## Overview

This role is designed to deploy CloudStack management and kvm hypervisor nodes.

This role is initially targeting Ubuntu, and tested on 24.04LTS.

## Core variables used by this role

***NOTE***: The cloudstack database is always named `cloud` and the usage
database is always `cloud_usage`.  There is no ability to change these.

- cloudstack_version - Release series to use. E.g. 4.19
- cloudstack_systemvm  - Path to download systemvm, E.g. "http://download.cloudstack.org/systemvm/4.19/systemvmtemplate-4.19.1-kvm.qcow2.bz2"
- mariadb_root_password
- cloudstack_db_user - defaults to 'cloudstack'
- cloudstack_db_password
- cloudstack_mgmt_key - encryption key used to store credentials in the Cloudstack properties file. Use text string like password.
- cloudstack_db_key - encryption key used to store credentials in the Cloudstack database. Use text string like password.
- cloudstack_ceph_fs - name of ceph fs to use for secondary storage
- cloudstack_mgmt_interface - name of cloudstack management interface (backend hypervisor communication)

## Configuring CloudStack

Secondary storage requires HTTPS, so you may get a network error unless TLS is configured properly as per https://www.shapeblue.com/securing-cloudstack-4-11-with-https-tls/
A workaround is to accept the certificate by going to https://{{ ssvm ip }} and accept the certificate then try again

