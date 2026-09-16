#!/usr/bin/env python3
"""Script used to sync from LDAP as a source of truth for Cloudstack"""

import configparser
import fnmatch
import random
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

import click
import ldap3
from cs import CloudStack

# Records when this script disabled an account, in the account's "accountdetails"
# map.  Cloudstack itself only reports "created", and keeping this on the account
# rather than on disk keeps the staggered per-node cron runs consistent.
DISABLED_SINCE_KEY = "ldapsync_disabled_since"

# Below the 1000 entry limit Okta's LDAP interface and AD both apply.
LDAP_PAGE_SIZE = 500

# Accounts always allowed to be disabled in one run, regardless of percentage.
# Without a floor the guard blocks ordinary departures on small deployments.
MIN_DISABLE_BEFORE_GUARD = 3

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
    state: str
    details: Dict[str, str] = field(default_factory=dict)
    disabled_since: Optional[datetime] = None


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
    groups: List[str]
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

    now = datetime.now(timezone.utc)

    # 0 (or a missing key, e.g. a stale config file) disables deletion entirely.
    delete_after_days = config_getint(config, "delete_disabled_after_days", 0)

    # Refuse to disable more than this share of the enabled accounts in one run.
    # 0 disables the check.
    max_disable_percent = config_getint(config, "max_disable_percent", 25)

    # Refuse to delete more than this many accounts in one run.  An absolute
    # count rather than a percentage: ordinary expiry is one or two accounts at
    # a time, so any percentage low enough to catch a bulk expiry also blocks
    # routine deletion on all but the largest deployments.  0 disables the check.
    max_delete_per_run = config_getint(config, "max_delete_per_run", 5)

    ldap_users, ldap_groups = fetch_ldap(config)
    cs_users, cs_projects, cs_roles, cs_idps, cs_nets = fetch_cloudstack(cs_client, config)

    project_groups = project_groups_list(config, ldap_groups)

    if dry_run:
        print("== DRY RUN ==")

    new_users = users_not_in(ldap_users, cs_users)
    absent_users = users_not_in(cs_users, ldap_users)

    enabled_accounts = [user for user in cs_users.values() if user.state.lower() == "enabled"]
    pending_disable = [user for user in absent_users if user.state.lower() == "enabled"]

    # An account re-enabled outside this script keeps the stamp we wrote, which
    # would short-circuit the retention window the next time it is disabled.
    # Locked accounts are cleared too: locking is an administrative hold, and a
    # stamp surviving across it would delete the account the moment an admin
    # unlocked it back to disabled, with no retention window at all.
    stale_stamps = [
        user
        for user in cs_users.values()
        if user.disabled_since is not None and user.state.lower() in ("enabled", "locked")
    ]

    # Only accounts that are actually disabled can expire.  Anything still
    # enabled is disabled further down, which restamps it, so it must not be
    # counted here or it would be deleted in the same run it was disabled.
    # "disabled" exactly, never "locked".  Locking is an administrative hold --
    # the state an admin puts a departing or investigated employee in -- and
    # nothing here ever lifts one, so deleting locked accounts would destroy
    # exactly the data someone had deliberately frozen.
    #
    # A stamp dated in the future means this node's clock disagrees with the one
    # that wrote it; skip rather than guess, since the arithmetic that decides
    # deletion is only as trustworthy as the clock behind it.
    expired_users = []
    if delete_after_days > 0:
        expired_users = [
            user
            for user in absent_users
            if user.state.lower() == "disabled"
            and user.disabled_since is not None
            and user.disabled_since <= now
            and (now - user.disabled_since).days >= delete_after_days
        ]

    # Both guards run before anything is modified.  A partial directory read
    # shows up as a mass disable; disables are measured against enabled accounts
    # only, so the growing pool of disabled ones does not creep the ratio up.
    # Deletion is guarded separately rather than relying on the disable guard
    # having seen these accounts: the stamping pass below admits accounts the
    # disable guard never counted, and they can expire together in one run.
    # A mass disable means the directory read is not trustworthy, and an
    # untrustworthy read poisons the membership reconciliation below just as
    # much as the disable pass, so this one aborts the whole run.
    check_guard(
        max_disable_percent,
        len(pending_disable),
        len(enabled_accounts),
        "enabled accounts",
        "are absent from LDAP",
        "This usually means the directory query returned incomplete results.",
        "max_disable_percent",
        min_exempt=MIN_DISABLE_BEFORE_GUARD,
    )

    # A mass expiry says nothing about the directory read, so this one skips
    # only the delete pass and lets the rest of the sync proceed.  It refuses
    # the deletions outright rather than trimming them to a per-run allowance:
    # an allowance would just spread the same bulk deletion over consecutive
    # runs, which on an hourly cron is a few hours rather than a refusal.
    if max_delete_per_run > 0 and len(expired_users) > max_delete_per_run:
        print(
            f" ! REFUSING to delete {len(expired_users)} accounts in one run, which exceeds "
            f"max_delete_per_run of {max_delete_per_run}."
        )
        print("   Deletion destroys every VM and volume these accounts own.")
        print("   A bulk expiry usually means accounts were stamped together rather than")
        print("   having left one at a time -- a pre-existing disabled population, or")
        print("   accounts disabled by hand, all reach their window on the same day.")
        print("   Nothing will be deleted until this is resolved.  Inspect with --dry-run;")
        print("   raise max_delete_per_run in the config if the expiry is genuine.")
        expired_users = []

    if len(new_users):
        print(f" * Adding {len(new_users)} new users")
        for user in new_users:
            cs_user_add(cs_client, user, cs_roles, cs_idps, dry_run)

    # Absence from LDAP is ambiguous (deactivated, dropped from a group, or an
    # incomplete read), so absent users are disabled and only deleted once they
    # have stayed that way for delete_disabled_after_days.  Their project and
    # network membership is left alone meanwhile, so nothing needs rebuilding on
    # reinstatement and the membership diff below must ignore them.
    retained_users = {user.username for user in absent_users}

    if len(stale_stamps):
        print(f" * Clearing stale disable time for {len(stale_stamps)} re-enabled users")
        for user in stale_stamps:
            print(f"   * Clearing {user.username}")
            if not dry_run:
                cs_user_set_disabled_since(cs_client, user, None)

    if len(pending_disable):
        print(f" * Disabling {len(pending_disable)} users")
        for user in pending_disable:
            cs_user_disable(cs_client, now, user, dry_run)

    # Already disabled but unstamped: first run after deployment, or disabled by
    # hand.  Start the clock now rather than retroactively.
    unstamped_users = [
        user for user in absent_users if user.state.lower() == "disabled" and user.disabled_since is None
    ]
    if len(unstamped_users):
        print(f" * Recording disable time for {len(unstamped_users)} already-disabled users")
        for user in unstamped_users:
            cs_user_stamp(cs_client, now, user, dry_run)

    # Destroys every VM and volume the account owns, and cannot be undone.
    if len(expired_users):
        print(f" * Deleting {len(expired_users)} users disabled for {delete_after_days}+ days")
        for user in expired_users:
            cs_user_del(cs_client, now, user, dry_run)

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

    updated_groups = modified_groups(project_groups, cs_projects, retained_users)
    if len(updated_groups):
        print(f" * Updating {len(updated_groups)} projects")
        for group in updated_groups:
            cs_project_mod(cs_client, group, cs_projects[group.name], ldap_users, dry_run)

    for _, network in cs_nets.items():
        ldap_network_groups_members = {}
        for group in network.groups:
            ldap_network_groups_members.update(ldap_groups[group].members)
        if set(network.members) - retained_users != set(ldap_network_groups_members):
            print(f" * Updating network {network.uuid} membership")
            cs_network_mod(cs_client, ldap_network_groups_members, network, ldap_users, dry_run)

    print("Sync Complete")


def abort(message: str) -> Exception:
    """
    Build an exception, printing it first.  The cron entry pipes stdout to
    syslog, so an operator sees one greppable ABORT line rather than only a
    traceback.

    Parameters:
        message [str]: Reason for aborting.

    Returns:
        Exception to raise.
    """

    print(f"ABORT: {message}")
    return Exception(message)


def config_getint(config: configparser.ConfigParser, key: str, fallback: int) -> int:
    """
    Read an integer setting, failing with a usable message rather than a
    ValueError traceback from deep inside configparser.

    Parameters:
        config [ConfigParser]: Parsed configuration
        key [str]: Key to read from the [cloudstack] section
        fallback [int]: Value to use when the key is absent

    Returns:
        int: The configured value, or fallback if the key is missing.

    Exceptions:
        Exception if the key is present but not an integer.
    """

    try:
        return config["cloudstack"].getint(key, fallback=fallback)
    except ValueError:
        raw = config["cloudstack"].get(key, fallback="")
        raise abort(f"{key} in the config must be an integer, got '{raw}'.  No changes have been made.")


def guard_exceeded(max_percent: int, count: int, total: int, min_exempt: int = 0) -> Optional[int]:
    """
    Decide whether count is an implausible share of total.

    Parameters:
        max_percent [int]: Percentage above which to refuse.  0 disables the check.
        count [int]: Number of accounts about to be acted on.
        total [int]: Population to measure against.
        min_exempt [int]: Allow up to this many regardless of share, for
            deployments small enough that any single departure is a large
            percentage.  0 means every count is measured.

    Returns:
        Optional[int]: The offending percentage, or None if within bounds.
    """

    if max_percent <= 0 or total <= 0 or count <= min_exempt:
        return None

    percent = (count * 100) // total
    if percent <= max_percent:
        return None

    return percent


def check_guard(
    max_percent: int,
    count: int,
    total: int,
    noun: str,
    verb: str,
    hint: str,
    setting: str,
    min_exempt: int = 0,
):
    """
    Abort the run if count is an implausible share of total.

    Parameters:
        max_percent [int]: Percentage above which to refuse.  0 disables the check.
        count [int]: Number of accounts about to be acted on.
        total [int]: Population to measure against.
        noun [str]: What total counts, for the message.
        verb [str]: What count is about to have happen, for the message.
        hint [str]: Why this is worth a second look.
        setting [str]: Config key to name in the message, so the operator has
            something to act on rather than just a refusal.
        min_exempt [int]: Allow up to this many regardless of share.

    Exceptions:
        Exception if the share exceeds max_percent.
    """

    percent = guard_exceeded(max_percent, count, total, min_exempt)
    if percent is None:
        return

    raise abort(
        f"{count} of {total} {noun} ({percent}%) {verb}, which exceeds {setting} of "
        f"{max_percent}%.  No changes have been made.  {hint}  Re-run with --dry-run to "
        f"inspect, or raise {setting} in the config if this is genuine."
    )


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

    if not user_match_state(ldap_user, cs_user):
        print("     * Enabling account")
        if not dry_run:
            client.enableAccount(id=cs_user.account_uuid)
            # Cleared so a later deactivation gets a fresh retention window.
            cs_user_set_disabled_since(client, cs_user, None)

    if not user_match_base(ldap_user, cs_user):
        print("     * Updating base data")
        if not dry_run:
            client.updateUser(
                id=cs_user.uuid, firstname=ldap_user.fname, lastname=ldap_user.lname, email=ldap_user.email
            )

    if not user_match_account(ldap_user, cs_user):
        print("     * Updating role")
        if not dry_run:
            # No accountdetails here on purpose: updateAccount only touches the
            # details map when the parameter is supplied, so the retention stamp
            # survives a role change untouched.
            #
            # newname is mandatory even when nothing about the name changes --
            # without it updateAccount fails with cserrorcode 4250 on 4.22, which
            # is why role changes have never actually applied.  It renames the
            # account, so it must be the name the server currently holds.
            account = cs_account_read(client, cs_user.account_uuid)
            if account is None:
                print(f"     - {cs_user.username} vanished before its role could be updated")
            else:
                client.updateAccount(
                    id=cs_user.account_uuid,
                    newname=account["name"],
                    roleid=cs_roles[ldap_user.role].uuid,
                )

    if not user_match_auth(ldap_user, cs_user):
        print("     * Updating authentication")
        if not dry_run:
            client.authorizeSamlSso(enable=True, userid=cs_user.uuid, entityid=next(iter(cs_idps.values())).id)


def cs_user_disable(client: CloudStack, now: datetime, user: User, dry_run: bool):
    """
    Disable an existing Cloudstack user whose account is no longer in LDAP.

    The account and its resources are preserved so the user can be reinstated.
    Disabling rather than locking also stops their running instances.

    Parameters:
        client [CloudStack]: Connected and logged in Cloudstack session
        now [datetime]: Timestamp recorded as the moment the account was disabled.
        user [User]: User to disable
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        CloudStackException
    """

    print(f"   * Disabling User {user.username}: {user.account_uuid}")
    if dry_run:
        return

    client.disableAccount(id=user.account_uuid, lock=False)
    cs_user_set_disabled_since(client, user, now)


def cs_user_stamp(client: CloudStack, now: datetime, user: User, dry_run: bool):
    """
    Record a disable timestamp on an account that is already disabled but has
    none, starting the retention clock from now.

    Parameters:
        client [CloudStack]: Connected and logged in Cloudstack session
        now [datetime]: Timestamp to record.
        user [User]: User to stamp
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        CloudStackException
    """

    print(f"   * Recording disable time for User {user.username}: {user.account_uuid}")
    if dry_run:
        return

    cs_user_set_disabled_since(client, user, now)


def cs_account_read(client: CloudStack, account_uuid: str) -> Optional[dict]:
    """
    Re-read a single account straight from Cloudstack.

    Matched by uuid rather than taken positionally, so this does not depend on
    the server having honoured the id filter.

    Parameters:
        client [CloudStack]: Connected and logged in Cloudstack session
        account_uuid [str]: Account to read

    Returns:
        Optional[dict]: The account, or None if it no longer exists.

    Exceptions:
        CloudStackException
    """

    for account in client.listAccounts(id=account_uuid, listall=True).get("account", []):
        if account.get("id") == account_uuid:
            return account
    return None


def cs_user_set_disabled_since(client: CloudStack, user: User, value: Optional[datetime]):
    """
    Write (or clear) the disable timestamp stored in the account's details map.

    Cloudstack merges the supplied keys into the account's existing details
    (AccountDetailsDaoImpl.update reads the current map, putAll's over it and
    rewrites it), so a key cannot be removed by leaving it out.  None therefore
    clears the timestamp by storing an empty string.

    The whole map is resent rather than just the one key, so this stays correct
    if those semantics are ever replace rather than merge.  Note the map comes
    from the snapshot fetch_cloudstack took at the start of the run, NOT from a
    fresh read -- a detail written by something else mid-run would be lost.

    Parameters:
        client [CloudStack]: Connected and logged in Cloudstack session
        user [User]: User whose details are updated
        value [Optional[datetime]]: Timestamp to record, or None to clear it.

    Exceptions:
        CloudStackException
    """

    # Re-read rather than reusing the snapshot fetch_cloudstack took at the top
    # of the run.  The whole map is resent, so writing the snapshot back would
    # revert anything added to this account's details since -- and those details
    # hold live credentials (Ceph RGW access/secret keys, for instance),
    # not just this stamp.  Every management node runs its own cron, so that
    # window is real.
    account = cs_account_read(client, user.account_uuid)
    if account is None:
        print(f"     - {user.username} vanished before its disable time could be written")
        return

    details = dict(account.get("accountdetails") or {})
    details[DISABLED_SINCE_KEY] = value.isoformat() if value is not None else ""

    # newname is mandatory: without it updateAccount fails with cserrorcode 4250
    # on 4.22.  It renames the account, so it has to be the name the server
    # currently holds -- taken from the read above, never reconstructed.
    client.updateAccount(id=user.account_uuid, newname=account["name"], accountdetails=details)
    user.details = details
    user.disabled_since = value


def cs_user_del(client: CloudStack, now: datetime, user: User, dry_run: bool):
    """
    Permanently delete an account disabled longer than the retention window.
    Destroys every resource it owns and cannot be undone.

    Parameters:
        client [CloudStack]: Connected and logged in Cloudstack session
        now [datetime]: Current time, used only to report how long the account
            has been disabled.
        user [User]: User to delete
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        CloudStackException
    """

    days = (now - user.disabled_since).days if user.disabled_since else -1
    print(f"   * Deleting User {user.username}: {user.account_uuid} (disabled {days} days)")
    if dry_run:
        return

    # Re-read immediately before destroying anything.  The decision to delete
    # was made from a snapshot taken at the top of the run, and every
    # management node runs this from its own cron entry, so another node (or an
    # admin) may have re-enabled the account in between.  Deleting on a stale
    # read is how a reinstated user loses everything.
    # Matched by uuid rather than taken positionally: this must not depend on
    # the server having honoured the id filter.
    current = cs_account_read(client, user.account_uuid)
    if current is None:
        print(f"     - vanished before deletion, skipping")
        return

    state = current.get("state", "").lower()
    if state != "disabled":
        print(f"     - now {state} rather than disabled, skipping")
        return

    stamp = parse_timestamp((current.get("accountdetails") or {}).get(DISABLED_SINCE_KEY))
    if stamp is None or stamp != user.disabled_since:
        print(f"     - disable timestamp changed since the run started, skipping")
        return

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
                # Users absent from LDAP are disabled and retained, not deleted, so
                # leave their membership alone; nothing needs rebuilding if they
                # are reinstated, and Cloudstack clears it if the account is
                # eventually deleted.
                if member not in ldap_users:
                    continue
                print(f"     * Removing member {member}")
                if not dry_run:
                    client.deleteAccountFromProject(
                        projectid=cs_project.uuid,
                        account=member,
                    )


def cs_network_mod(client: CloudStack, ldap_group_members: Dict[str, None], network: Network, ldap_users: Dict[str, User], dry_run: bool):
    """
    Modify Network account membership.

    Parameters:
        client [ClientStack]: Connected and logged in CloudStack session
        ldap_group_members [Dict[str, None]]: Updated group from LDAP
        network [Network]: Network to compare membership
        ldap_users [Dict[str, User]]: List of known users in LDAP.  Used to exclude group membership changes for
            deleted users.
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        CloudStackException
    """

    print(f"   * Updating Network {network.uuid}")

    for member in ldap_group_members:
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
        if member not in ldap_group_members:
            # Retained users keep their access for the same reason as project
            # membership above.
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


def parse_timestamp(val: Optional[str]) -> Optional[datetime]:
    """
    Anything missing, empty or unparseable is treated as "no timestamp", which
    restamps the account rather than deleting it.

    Parameters:
        val [Optional[str]]: ISO 8601 timestamp, or None.

    Returns:
        Timezone aware datetime if parseable, otherwise None.
    """

    if not val:
        return None

    try:
        parsed = datetime.fromisoformat(val)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


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


def ldap_search(conn: "ldap3.Connection", search_base: str, description: str) -> List[Dict]:
    """
    Perform a paged LDAP search and return every entry beneath search_base.

    Servers cap result sets (commonly at 1000 entries) and report
    sizeLimitExceeded alongside a *partial* result rather than an error, so an
    unpaged search silently sees a truncated directory -- which here reads as
    users having left.  Hence paging, and checking the result code rather than
    only testing the response for None.

    Parameters:
        conn [ldap3.Connection]: Bound LDAP connection
        search_base [str]: DN to search beneath
        description [str]: Human readable name used in error messages

    Returns:
        entries [List[Dict]]: Every searchResEntry returned by the server.

    Exceptions:
        LDAPException
        Exception if the search failed or returned nothing at all.
    """

    entries = []
    for row in conn.extend.standard.paged_search(
        search_base=search_base,
        search_filter="(objectclass=*)",
        attributes=ldap3.ALL_ATTRIBUTES,
        paged_size=LDAP_PAGE_SIZE,
        # Without this the control is advisory: a server that does not support
        # paging ignores it and answers with a single silently truncated page
        # and result code 0, which is precisely the truncation paging is here to
        # catch.  Critical makes such a server refuse the search instead.
        paged_criticality=True,
        generator=True,
    ):
        # Referrals and other non-entry responses carry no attributes.
        if row.get("type") != "searchResEntry":
            continue
        entries.append(row)

    result = conn.result or {}
    if result.get("result"):
        raise abort(
            f"{description} search failed: {result.get('description')} ({result.get('message')})"
        )

    # Never legitimate, and would otherwise read as "everyone has left".
    if not entries:
        raise abort(f"{description} search under {search_base} returned no entries")

    return entries


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

    group_entries = ldap_search(conn, config["ldap"]["groupdn"], "group")

    groups = {}
    for row in group_entries:
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

    user_entries = ldap_search(conn, config["ldap"]["userdn"], "user")

    users = {}
    for row in user_entries:
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
            state="enabled",
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
    ignore_users.append("admin")
    ignore_projects = config["cloudstack"]["ignore_projects"].split(",")
    list_networks = {}
    for network in config["cloudstack"]["network_groups"].split(","):
        network = network.strip()
        if len(network) > 0:
            network = network.split("=")
            list_networks[network[0]] = network[1].split(";")

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

        details = account.get("accountdetails") or {}

        user = User(
            username=u["username"],
            account_uuid=account["id"],
            uuid=u["id"],
            fname=u["firstname"],
            lname=u["lastname"],
            email=u.get("email"),
            role=account["rolename"],
            usersource=u["usersource"],
            state=account["state"],
            details=details,
            disabled_since=parse_timestamp(details.get(DISABLED_SINCE_KEY)),
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
    for uuid, netgroups in list_networks.items():
        members = {}
        csnets = cs_client.listNetworkPermissions(networkid=uuid)
        for member in csnets["networkpermission"]:
            if "project" in member:
                continue
            members[member["account"]] = None
        networks[uuid] = Network(uuid=uuid, groups=netgroups, members=members)

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

    list2_casefold = { x.casefold() for x in list2 }

    return [user for user in list1.values() if user.username.casefold() not in list2_casefold]


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
    list2_casefold = { x.casefold() for x in list2 }
    return [g for g in list1.values() if g.name.casefold() not in list2_casefold and (g.enabled or not ignore_list1_disabled)]


def user_match_auth(ldap_user: User, cs_user: User) -> bool:
    if ldap_user.usersource != cs_user.usersource:
        return False
    return True


def user_match_state(ldap_user: User, cs_user: User) -> bool:
    # "locked" is an administrative hold this script never applies, so it is not
    # ours to lift.  Only a plain "disabled" is reversed on reinstatement.
    if cs_user.state.lower() == "locked":
        return True
    if ldap_user.state.lower() != cs_user.state.lower():
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

    if not user_match_state(ldap_user, cs_user):
        return False
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


def group_match(ldap_group: Group, cs_group: Group, retained_users: Set[str]) -> bool:
    """
    Determine if the 2 groups are identical.

    Parameters:
        ldap_group [Group]: LDAP group
        cs_group [Group]: Cloudstack group
        retained_users [Set[str]]: Cloudstack accounts kept but disabled because
            they are absent from LDAP.  Their project membership is left as-is,
            so it must not count as a difference.

    Returns:
        match [bool]: Whether or not group data matches
    """

    if ldap_group.enabled != cs_group.enabled:
        return False

    if set(ldap_group.members) != set(cs_group.members) - retained_users:
        return False

    return True


def modified_groups(
    ldap_groups: Dict[str, Group], cs_groups: Dict[str, Group], retained_users: Set[str]
) -> List[Group]:
    """
    Determine the list of modified groups.

    Parameters:
        ldap_groups [Dict[str, Group]]: Group list from LDAP
        cs_groups [Dict[str, Group]]: Group list from Cloudstack
        retained_users [Set[str]]: Cloudstack accounts kept but disabled because
            they are absent from LDAP.

    Returns:
        users [List[Groups]]: List of modified groups.  Excludes Added and Deleted groups.
    """
    groups = []
    for ldap_group in ldap_groups.values():
        cs_group = cs_groups.get(ldap_group.name)
        if cs_group is None:
            continue
        if group_match(ldap_group, cs_group, retained_users):
            continue
        groups.append(ldap_group)
    return groups


if __name__ == "__main__":
    sync()
