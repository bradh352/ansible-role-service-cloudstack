#!/usr/bin/env python3
"""Script used to sync from LDAP as a source of truth for Cloudstack"""

import configparser
import fnmatch
import random
import string
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import click
import ldap3
from cs import CloudStack

@dataclass
class User:
    """Data class containing all user attributes we care about"""

    username: str
    fname: str
    lname: str
    email: Optional[str]
    account_uuid: Optional[str]
    uuid: Optional[str]
    role: str
    usersource: str


@dataclass
class Group:
    """Data class containing all group attributes we care about"""

    name: str
    enabled: bool
    members: Dict[str, None]
    uuid: Optional[str]


@dataclass
class Network:
    """Data class containing permissions for a Network"""

    uuid: str
    group: str
    members: Dict[str, None]


@dataclass
class Role:
    """Data class containing all role attributes we care about"""

    uuid: Optional[str]
    name: str


@dataclass
class IDP:
    """Data clas containing IdP metadata"""

    id: str
    orgname: str
    orgurl: Optional[str]


@click.command()
@click.option(
    "--config-path",
    type=click.Path(exists=True, readable=True),
    default="/etc/cloudstack/ldapsync.conf",
    help="Configuration Path.",
)
@click.option(
    "--cloudmonkey-config-path",
    type=click.Path(exists=True, readable=True),
    default="/root/.cmk/config",
    help="Cloudmonkey Configuration Path.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Output what would be done",
)
def sync(config_path: str, cloudmonkey_config_path: str, dry_run: bool):
    """Sync users and groups from LDAP to Cloudstack"""
    config = configparser.ConfigParser()
    config.read(config_path)

    # Cloudmonkey config has parameters outside of a section at the beginning,
    # Lets put that into a [default] section.
    cmk_config = configparser.ConfigParser()
    with open(cloudmonkey_config_path) as c:
        cmk_config.read_string("[default]\n" + c.read())

    cs_client = CloudStack(
        endpoint=cmk_config["localcloud"]["url"],
        key=cmk_config["localcloud"]["apikey"],
        secret=cmk_config["localcloud"]["secretkey"],
        timeout=60, # Cloudstack on create operations can be slow.
    )

    ldap_users, ldap_groups = fetch_ldap(config)
    cs_users, cs_projects, cs_roles, cs_idps, cs_nets = fetch_cloudstack(cs_client, config)

    project_groups = project_groups_list(config, ldap_groups)

    if dry_run:
        print("== DRY RUN ==")

    new_users = users_not_in(ldap_users, cs_users)
    if len(new_users):
        print(f" * Adding {len(new_users)} new users")
        for user in new_users:
            cs_user_add(cs_client, user, cs_roles, cs_idps, dry_run)

    deleted_users = users_not_in(cs_users, ldap_users)
    if len(deleted_users):
        print(f" * Deleting {len(deleted_users)} users")
        for user in deleted_users:
            cs_user_del(cs_client, user, dry_run)

    new_groups = groups_not_in(project_groups, cs_projects)
    if len(new_groups):
        print(f" * Adding {len(new_groups)} new projects")
        for group in new_groups:
            cs_project_add(cs_client, group, dry_run)

    # In case of user error, we suspend instead of delete projects
    deleted_groups = groups_not_in(cs_projects, project_groups, ignore_list1_disabled=True)
    if len(deleted_groups):
        print(f" * Suspending {len(deleted_groups)} projects")
        for group in deleted_groups:
            cs_project_suspend(cs_client, group, dry_run)

    updated_users = modified_users(ldap_users, cs_users)
    if len(updated_users):
        print(f" * Updating {len(updated_users)} users")
        for user in updated_users:
            cs_user_mod(cs_client, user, cs_users[user.username], cs_roles, cs_idps, dry_run)

    updated_groups = modified_groups(project_groups, cs_projects)
    if len(updated_groups):
        print(f" * Updating {len(updated_groups)} projects")
        for group in updated_groups:
            cs_project_mod(cs_client, group, cs_projects[group.name], ldap_users, dry_run)

    for _, network in cs_nets.items():
        if network.members != ldap_groups[network.group].members:
            print(f" * Updating network {network.uuid} membership")
            cs_network_mod(cs_client, ldap_groups[network.group], network, ldap_users, dry_run)

    print("Sync Complete")


def cs_user_add(client: CloudStack, user: User, cs_roles: Dict[str, Role], cs_idps: Dict[str, IDP], dry_run: bool):
    """
    Add a user into Cloudstack

    Parameters:
        client [CloudStack]: Connected and logged in CloudStack session
        user [User]: User attributes to add
        cs_roles [Dict[str, Role]]: Dictionary of Cloudstack roles
        cs_idps [Dict[str, IDP]]: Dictionary of IDP providers
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        CloudStackException
    """

    print(f"   * Adding User {user.username}")
    if dry_run:
        return

    result = client.createAccount(
        email=user.email,
        firstname=user.fname,
        lastname=user.lname,
        # Generate random password and throw it away.  We are using SAML auth but Cloudstack requires a password.
        password=''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20)),
        username=user.username,
        roleid=cs_roles[user.role].uuid,
    )

    # Save updated data
    user.account_uuid = result["account"]["id"]
    user.uuid = result["account"]["user"][0]["id"]
    client.authorizeSamlSso(enable=True, userid=user.uuid, entityid=next(iter(cs_idps.values())).id)


def cs_user_mod(
    client: CloudStack,
    ldap_user: User,
    cs_user: User,
    cs_roles: Dict[str, Role],
    cs_idps: Dict[str, IDP],
    dry_run: bool
):
    """
    Modify existing Cloudstack user.

    Parameters:
        client [CloudStack]: Connected and logged in CloudStack session
        ldap_user [User]: User attributes to modify
        cs_user [User]: Current user data in Cloudstack
        cs_roles [Dict[str, Role]]: List of cloudstack roles.
        cs_idps [Dict[str, IDP]]: Dictionary of IDP providers
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        CloudStackException
    """

    print(f"   * Updating User {ldap_user.username}")

    if not user_match_base(ldap_user, cs_user):
        print("     * Updating base data")
        if not dry_run:
            client.updateUser(
                id=cs_user.uuid, firstname=ldap_user.fname, lastname=ldap_user.lname, email=ldap_user.email
            )

    if not user_match_account(ldap_user, cs_user):
        print("     * Updating role")
        if not dry_run:
            client.updateAccount(id=cs_user.account_uuid, roleid=cs_roles[ldap_user.role].uuid)

    if not user_match_auth(ldap_user, cs_user):
        print("     * Updating authentication")
        if not dry_run:
            client.authorizeSamlSso(enable=True, userid=cs_user.uuid, entityid=next(iter(cs_idps.values())).id)


def cs_user_del(client: CloudStack, user: User, dry_run: bool):
    """
    Delete existing Cloudstack user.

    Parameters:
        client [CloudStack]: Connected and logged in Cloudstack session
        user [User]: User to delete
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        CloudStackException
    """

    print(f"   * Deleting User {user.username}: {user.account_uuid}")
    if dry_run:
        return

    # Disable account first then delete.  Delete in theory could fail if the
    # account is a resource owner of something like a Project, which hopefully
    # won't actually happen.
    client.disableAccount(id=user.account_uuid, lock=False)
    client.deleteAccount(id=user.account_uuid)


def cs_project_add(client: CloudStack, group: Group, dry_run: bool):
    """
    Add Cloudstack project based on Group and members

    Parameters:
        client [CloudStack]: Connected and logged in Cloudstack session
        group [Group]: Group to add with members
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        CloudStackException
    """

    print(f"   * Adding Project {group.name}")

    if not dry_run:
        result = client.createProject(
            name=group.name
        )
        group.uuid = result["id"]

    if len(group.members):
        print(f"     * Adding {len(group.members)} members")
        for member in group.members:
            print(f"       * Adding member {member}")
            if not dry_run:
                client.addAccountToProject(
                    projectid=group.uuid,
                    account=member,
                )


def cs_project_mod(
    client: CloudStack, ldap_group: Group, cs_project: Group, ldap_users: Dict[str, User], dry_run: bool
):
    """
    Modify CloudStack group.  Will also update group membership

    Parameters:
        client [ClientStack]: Connected and logged in CloudStack session
        ldap_group [Group]: Updated group from LDAP
        cs_project [Group]: Current cloudstack project.  Used to compare changes such as group membership.
        ldap_users [Dict[str, User]]: List of known users in LDAP.  Used to exclude group membership changes for
            deleted users.
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        CloudStackException
    """

    print(f"   * Updating Project {cs_project.name}")

    # This is only called if the project was previously deactivated but still exists and should be active.
    if ldap_group.enabled != cs_project.enabled:
        print(f"     * Activating project")
        if not dry_run:
            client.activateProject(id=cs_project.uuid)

    # Change in group membership
    if ldap_group.members != cs_project.members:
        for member in ldap_group.members:
            if member not in cs_project.members:
                print(f"     * Adding member {member}")
                if not dry_run:
                    client.addAccountToProject(
                        projectid=cs_project.uuid,
                        account=member,
                    )
        for member in cs_project.members:
            if member not in ldap_group.members:
                # On user deletion, we've pre-cached group membership, but it will be auto-removed so skip
                # deleted users.
                if member not in ldap_users:
                    continue
                print(f"     * Removing member {member}")
                if not dry_run:
                    client.deleteAccountFromProject(
                        projectid=cs_project.uuid,
                        account=member,
                    )


def cs_network_mod(client: CloudStack, ldap_group: Group, network: Network, ldap_users: Dict[str, User], dry_run: bool):
    """
    Modify Network account membership.

    Parameters:
        client [ClientStack]: Connected and logged in CloudStack session
        ldap_group [Group]: Updated group from LDAP
        network [Network]: Network to compare membership
        ldap_users [Dict[str, User]]: List of known users in LDAP.  Used to exclude group membership changes for
            deleted users.
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        CloudStackException
    """

    print(f"   * Updating Network {network.uuid}")

    for member in ldap_group.members:
        if member not in network.members:
            # We may have a member that isn't actually in the system, skip
            if member not in ldap_users:
                continue
            print(f"     * Adding member {member}")
            if not dry_run:
                client.createNetworkPermissions(
                    networkid=network.uuid,
                    accounts=member,
                )
    for member in network.members:
        if member not in ldap_group.members:
            # On user deletion, we've pre-cached group membership, but it will be auto-removed so skip
            # deleted users.
            if member not in ldap_users:
                continue
            print(f"     * Removing member {member}")
            if not dry_run:
                client.removeNetworkPermissions(
                    networkid=network.uuid,
                    accounts=member,
                )


def cs_project_suspend(client: CloudStack, group: Group, dry_run: bool):
    """
    Suspend cloudstack project

    Parameters:
        client [Cloudstack]: Connected and logged in CloudStack session
        group [Group]: Group to delete
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        CloudStackException
    """

    print(f"   * Suspending Project {group.name}")
    if not dry_run:
        client.suspendProject(id=group.uuid)


def fetch_string(values: Dict, name: Optional[str]) -> Optional[str]:
    """
    Fetch a string value from a dictionary.  If the value located is a list,
    will return the first entry in the list.  If the value located is a byte
    array, will convert it to utf-8.

    Parameters:
        values [Dict]: Dictionary to query for string
        name [str]: Name to search in dictionary

    Returns:
        String value if found otherwise None
    """

    if name is None or len(name) == 0:
        return None

    val = values.get(name)
    if not val:
        return None

    if isinstance(val, list):
        val = val[0]

    if isinstance(val, bytes):
        val = val.decode("utf-8")

    if not isinstance(val, str):
        val = str(val)

    return val


def fetch_required_string(values: dict, name: str) -> str:
    """
    Fetch a string value from a dictionary.  If the value located is a list,
    will return the first entry in the list.  If the value located is a byte
    array, will convert it to utf-8.

    Parameters:
        values [Dict]: Dictionary to query for string
        name [str]: Name to search in dictionary

    Returns:
        String value

    Exceptions:
        Exception if name is invalid or value not found.
    """

    if len(name) == 0:
        raise Exception("name must have length greater than 0")

    val = fetch_string(values, name)
    if val is None:
        raise Exception(f"{name} does not exist")

    return val


def strtobool(val: str) -> bool:
    """
    Convert provided string value into a boolean.

    Supports y, yes, t, true, on, 1 as truth values, all other values are False.

    Parameters:
        val [str]: value to interpret

    Returns:
        bool
    """

    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return True
    return False


def project_groups_list(config: configparser.ConfigParser, groups: Dict[str, Group]) -> Dict[str, Group]:
    project_groups = config["ldap"]["project_groups"].split(",")
    out = {}
    for name, data in groups.items():
        for groupname in project_groups:
            if fnmatch.fnmatch(name, groupname):
                out[name] = data
                break
    return out


def fetch_ldap(config: configparser.ConfigParser) -> Tuple[Dict[str, User], Dict[str, Group]]:
    """
    Retrieve all users that belong to groups_allowed or project_groups, and return group for each project_group with
    membership.

    Parameters:
        config [ConfigParser]: Configuration containing "ldap" section with appropriate parameters

    Returns:
        Users [Dict[str, User]]: Dictionary of users.  The key is the username, the value is a class User instance.
        Groups [Dict[str, Group]]: Dictionary of groups. The key is the group name, the value is a class Group instance.

    Exceptions:
        LDAPException
        Exception
    """

    server = ldap3.Server(config["ldap"]["server"], use_ssl=strtobool(config["ldap"]["use_ssl"]))
    conn = ldap3.Connection(server, config["ldap"]["binddn"], config["ldap"]["bindpass"], auto_bind=True)

    ignore_users = config["ldap"]["ignore_users"].split(",")
    project_groups = config["ldap"]["project_groups"].split(",")
    admin_groups = config["ldap"]["admin_groups"].split(",")
    groups_allowed = config["ldap"]["groups_allowed"].split(",")
    groups_allowed.extend(project_groups)
    groups_allowed.extend(admin_groups)
    groups_allowed = list(set(groups_allowed))

    # Transform user list into dictionaries for faster lookups
    # We don't do this for groups since we do an fnmatch() on those.
    ignore_users = { user for user in ignore_users }

    all_allowed_users = {}
    admin_users = {}

    conn.search(
        search_base=config["ldap"]["groupdn"],
        search_filter="(objectclass=*)",
        attributes=ldap3.ALL_ATTRIBUTES,
    )

    if conn.response is None:
        raise Exception("group search failed")

    groups = {}
    for row in conn.response:
        attr = row["raw_attributes"]

        name = fetch_string(attr, config["ldap"]["attr_group"])
        if name is None:
            continue

        # Determine if this group allows the user.
        allowed_user_group_match = False
        for groupname in groups_allowed:
            if fnmatch.fnmatch(name, groupname):
                allowed_user_group_match = True
                break

        members = {}
        if attr.get(config["ldap"]["attr_group_members"]):
            for member in attr.get(config["ldap"]["attr_group_members"]):
                member = member.decode("utf-8")
                member = member.split(",")[0]
                member = member.split("=")[1]
                if member in ignore_users:
                    continue
                members[member] = None

                # We keep a list of all allowed users
                if allowed_user_group_match:
                    all_allowed_users[member] = None

                # If the group is an administrative group, also cache the user as an admin user
                admin_group_match = False
                for groupname in admin_groups:
                    if fnmatch.fnmatch(name, groupname):
                        admin_group_match = True
                        break

                if admin_group_match:
                    admin_users[member] = None

        # Always save the group as we need it for things like network maps
        group = Group(
            name=name,
            members=members,
            enabled=True,
            uuid=None,
        )

        groups[group.name] = group

    conn.search(
        search_base=config["ldap"]["userdn"],
        search_filter="(objectclass=*)",
        attributes=ldap3.ALL_ATTRIBUTES,
    )

    if conn.response is None:
        raise Exception("user search failed")

    users = {}
    for row in conn.response:
        attr = row["raw_attributes"]

        username = fetch_string(attr, config["ldap"]["attr_username"])
        if username is None or username not in all_allowed_users:
            continue

        user = User(
            username=username,
            fname=fetch_required_string(attr, config["ldap"]["attr_fname"]),
            lname=fetch_required_string(attr, config["ldap"]["attr_lname"]),
            email=fetch_string(attr, config["ldap"].get("attr_email")),
            role="Root Admin" if username in admin_users else "User",
            usersource="saml2",
            uuid=None,
            account_uuid=None,
        )

        if user.username in users:
            raise Exception(f"Duplicate user {user.username}")

        users[user.username] = user

    return users, groups


def fetch_cloudstack(
    cs_client: CloudStack, config: configparser.ConfigParser
) -> Tuple[Dict[str, User], Dict[str, Group], Dict[str, Role], Dict[str, IDP], Dict[str, Network]]:
    """
    Retrieve all cloudstack users (that are not in ignore_users), all projects (as groups), and all roles (for
    dereferencing UUIDs)

    Parameters:
        cs_client [CloudStack]: Initialized and Logged in Cloudstack user
        config [ConfigParser]: Configuration containing "ldap" section with appropriate parameters

    Returns:
        Users [Dict[str, User]]: Dictionary of users.  The key is the username, the value is a class User instance.
        Groups [Dict[str, Group]]: Dictionary of groups. The key is the group name, the value is a class Group instance.
        Roles [Dict[str, Role]]: Dictionary of roles. The key is the role name, the value is a class Role instance.
        IDPs [Dict[str, Role]]: Dictionary of IDPs.  The key is the orgName, the value is a class IDP instance.
        Networks [Dict[str, Network]]: Dictionary of Networks that are configured with members. The key is the network uuid, the value is a class Network instance.

    Exceptions:
        CloudStackException
    """

    ignore_users = config["cloudstack"]["ignore_users"].split(",")
    # Internal system account, filter out, says should never be deleted:
    #   https://cwiki.apache.org/confluence/display/CLOUDSTACK/Baremetal+Advanced+Networking+Support
    ignore_users.append("baremetal-system-account")
    ignore_projects = config["cloudstack"]["ignore_projects"].split(",")
    list_networks = {}
    for network in config["cloudstack"]["network_groups"].split(","):
        network = network.strip()
        if len(network) > 0:
            network = network.split("=")
            list_networks[network[0]] = network[1]

    users = {}
    csusers = cs_client.listAccounts(listall=True)
    for account in csusers["account"]:
        # Configured users to ignore, and ignore kubeadmin-* users that are auto-generated by the k8s integration
        if account["name"] in ignore_users or account["name"].startswith("kubeadmin-"):
            continue

        # Cloudstack has a weird concept of user aliases.  Only match a user with the same name as the account.
        u = None
        for user in account["user"]:
            if account["name"] == user["username"]:
                u = user
                break

        if u is None:
            raise Exception(f"Account {account['name']} is expected to have a username of an equivalent name.")

        user = User(
            username=u["username"],
            account_uuid=account["id"],
            uuid=u["id"],
            fname=u["firstname"],
            lname=u["lastname"],
            email=u.get("email"),
            role=account["rolename"],
            usersource=u["usersource"],
        )
        users[user.username] = user

    groups = {}
    projects = cs_client.listProjects(listall=True)
    if projects.get("project"):
        for project in projects["project"]:
            if project["name"] in ignore_projects:
                continue

            accounts = cs_client.listProjectAccounts(projectid=project["id"])
            members = {}
            # This lists
            for account in accounts["projectaccount"]:
                # Yes, this is an odd format due to an account potentially having alias users.  We don't support that, so
                # we always just use the first index.
                username = account["user"][0]["account"]
                if username in ignore_users:
                    continue
                members[username] = None

            group = Group(
                uuid=project["id"],
                name=project["name"],
                members=members,
                enabled=True if project["state"] == "Active" else False,
            )
            groups[group.name] = group

    roles = {}
    csroles = cs_client.listRoles()
    for csrole in csroles["role"]:
        role = Role(
            uuid=csrole["id"],
            name=csrole["name"],
        )
        roles[role.name] = role

    idps = {}
    csidps = cs_client.listIdps()
    if csidps.get("idp"):
        for csidp in csidps["idp"]:
            idp = IDP(
                id=csidp["id"],
                orgname=csidp["orgName"],
                orgurl=csidp.get("orgUrl")
            )
            idps[idp.orgname] = idp

    networks = {}
    for uuid, group in list_networks.items():
        members = {}
        csnets = cs_client.listNetworkPermissions(networkid=uuid)
        for member in csnets["networkpermission"]:
            if "project" in member:
                continue
            members[member["account"]] = None
        networks[uuid] = Network(uuid=uuid, group=group, members=members)

    return users, groups, roles, idps, networks


def users_not_in(list1: Dict[str, User], list2: Dict[str, User]) -> List[User]:
    """
    Output list of users in list1 that are not in list2

    Parameters:
       list1 [Dict[str, User]]: List of desired users
       list2 [Dict[str, User]]: List of possible users

    Returns:
        users List[User]: list of users in list1 that are not in list2
    """

    return [user for user in list1.values() if user.username not in list2]


def groups_not_in(list1: Dict[str, Group], list2: Dict[str, Group], ignore_list1_disabled: bool = False) -> List[Group]:
    """
    Output list of groups in list1 that are not in list2, and ignore groups in
    list 2 that are not enabled.

    Parameters:
       list1 [Dict[str, Group]]: List of desired groups
       list2 [Dict[str, Group]]: List of possible groups
       ignore_list1_disabled [bool]: Ignore list1 members that are disabled.

    Returns:
        users List[Group]: list of groups in list1 that are not in list2, possibly filtering out disabled list1 groups
    """
    return [g for g in list1.values() if g.name not in list2 and (g.enabled or not ignore_list1_disabled)]


def user_match_auth(ldap_user: User, cs_user: User) -> bool:
    if ldap_user.usersource != cs_user.usersource:
        return False
    return True


def user_match_account(ldap_user: User, cs_user: User) -> bool:
    if ldap_user.role != cs_user.role:
        return False
    return True


def user_match_base(ldap_user: User, cs_user: User) -> bool:
    if ldap_user.fname != cs_user.fname:
        return False
    if ldap_user.lname != cs_user.lname:
        return False
    if ldap_user.email is not None and ldap_user.email != cs_user.email:
        return False
    return True


def user_match(ldap_user: User, cs_user: User) -> bool:
    """
    Determine if the 2 users are identical.  If email, uid, or shell are not
    available in the IDP, will not check for match on those attributes.

    Parameters:
        ldap_user [User]: LDAP
        cs_user [User]: Cloudstack user

    Returns:
        match [bool]: Whether or not user data matches
    """

    if not user_match_base(ldap_user, cs_user):
        return False
    if not user_match_account(ldap_user, cs_user):
        return False
    if not user_match_auth(ldap_user, cs_user):
        return False

    return True


def modified_users(ldap_users: Dict[str, User], cs_users: Dict[str, User]) -> List[User]:
    """
    Determine the list of modified users.

    Parameters:
        ldap_users [Dict[str, User]]: User list from LDAP
        cs_users [Dict[str, User]]: User list from Cloudstack

    Returns:
        users [List[Users]]: List of modified users.  Excludes Added and Deleted users.
    """

    users = []
    for ldap_user in ldap_users.values():
        cs_user = cs_users.get(ldap_user.username)
        if cs_user is None:
            continue
        if user_match(ldap_user, cs_user):
            continue
        users.append(ldap_user)
    return users


def group_match(ldap_group: Group, cs_group: Group) -> bool:
    """
    Determine if the 2 groups are identical.

    Parameters:
        ldap_group [Group]: LDAP group
        cs_group [Group]: Cloudstack group

    Returns:
        match [bool]: Whether or not group data matches
    """

    if ldap_group.enabled != cs_group.enabled:
        return False

    if ldap_group.members != cs_group.members:
        return False

    return True


def modified_groups(ldap_groups: Dict[str, Group], cs_groups: Dict[str, Group]) -> List[Group]:
    """
    Determine the list of modified groups.

    Parameters:
        ldap_groups [Dict[str, Group]]: Group list from LDAP
        cs_groups [Dict[str, Group]]: Group list from Cloudstack

    Returns:
        users [List[Groups]]: List of modified groups.  Excludes Added and Deleted groups.
    """
    groups = []
    for ldap_group in ldap_groups.values():
        cs_group = cs_groups.get(ldap_group.name)
        if cs_group is None:
            continue
        if group_match(ldap_group, cs_group):
            continue
        groups.append(ldap_group)
    return groups


if __name__ == "__main__":
    sync()
