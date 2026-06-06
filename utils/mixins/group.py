#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Group Management Mixin — 组管理命令 (9 个)
"""

import ldap3
from ldap3.utils.conv import escape_filter_chars

from utils.ui import print_info, print_success, print_found, print_warn
from utils.helpers import (
    parse_args, check_result, get_dn, get_entry,
    display_entry, display_entries, LDAP_MATCHING_RULE_IN_CHAIN,
    paged_search,
)


class GroupMixin:
    """Group Management 命令集"""

    # ── add_group ─────────────────────────────────────────────
    def do_add_group(self, line):
        """add_group <group> — 创建组"""
        args = parse_args(line, 1, 1, "add_group MyGroup")

        group_dn = 'CN=%s,CN=Users,%s' % (args[0], self.domain_dumper.root)
        ucd = {
            'sAMAccountName': args[0],
            'cn': args[0],
        }
        print_info("Creating group: %s" % group_dn)
        res = self.client.add(group_dn, ['top', 'group'], ucd)
        if not res:
            raise Exception("Failed: %s" % self.client.result.get('description', ''))
        print_success("Group created: %s" % args[0])

    # ── delete_group ──────────────────────────────────────────
    def do_delete_group(self, line):
        """delete_group <group> — 删除组"""
        args = parse_args(line, 1, 1, "delete_group MyGroup")
        dn = get_dn(self.client, self.domain_dumper, args[0])
        if not dn:
            raise Exception("Group not found: %s" % args[0])

        print_info("Deleting group: %s" % dn)
        self.client.delete(dn)
        check_result(self.client, "Group %s deleted" % args[0])

    # ── get_group ─────────────────────────────────────────────
    def do_get_group(self, line):
        """get_group <group> — 查看组详情"""
        args = parse_args(line, 1, 1, "get_group 'Domain Admins'")
        entry = get_entry(self.client, self.domain_dumper, args[0])
        if not entry:
            raise Exception("Group not found: %s" % args[0])
        display_entry(entry)

    # ── list_groups ───────────────────────────────────────────
    def do_list_groups(self, line):
        """list_groups — 枚举所有组"""
        print_info("Enumerating groups...")
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=group)',
            attributes=['sAMAccountName', 'description', 'groupType'],
        )
        print_success("Found %d group(s)" % len(entries))
        display_entries(entries, ['sAMAccountName', 'description'])

    # ── group_members ─────────────────────────────────────────
    def do_group_members(self, line):
        """group_members <group> — 查看组成员"""
        args = parse_args(line, 1, 1, "group_members 'Domain Admins'")
        dn = get_dn(self.client, self.domain_dumper, args[0])
        if not dn:
            raise Exception("Group not found: %s" % args[0])

        # 递归查询所有成员 (含嵌套组)
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(memberof:%s:=%s)' % (LDAP_MATCHING_RULE_IN_CHAIN, escape_filter_chars(dn)),
            attributes=['sAMAccountName', 'distinguishedName'],
        )
        for entry in entries:
            print_found("%s (%s)" % (entry['sAMAccountName'].value, entry.entry_dn))

    do_get_group_users = do_group_members  # 向后兼容别名

    # ── group_owner ───────────────────────────────────────────
    def do_group_owner(self, line):
        """group_owner <group> — 查看组 Owner"""
        from ldap3.protocol.microsoft import security_descriptor_control

        args = parse_args(line, 1, 1, "group_owner 'Domain Admins'")

        controls = security_descriptor_control(sdflags=0x01)
        entry = get_entry(self.client, self.domain_dumper, args[0],
                          ['nTSecurityDescriptor'], controls=controls)
        if not entry:
            raise Exception("Group not found: %s" % args[0])

        from impacket.ldap import ldaptypes
        try:
            sd_data = entry['nTSecurityDescriptor'].raw_values[0]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
            owner_sid = sd['OwnerSid'].formatCanonical()
            owner_name = self._resolve_sid(owner_sid)
            if owner_name:
                print_found("Owner: %s (%s)" % (owner_name, owner_sid))
            else:
                print_found("Owner SID: %s" % owner_sid)
        except (IndexError, KeyError):
            print_warn("Unable to read security descriptor — permission denied or SD not available")
            print_info("Hint: Reading nTSecurityDescriptor typically requires administrative privileges")

    # ── add_group_member (别名: add_user_to_group) ────────────
    def do_add_group_member(self, line):
        """add_group_member <group> <user> — 添加成员到组"""
        args = parse_args(line, 2, 2, "add_group_member 'Domain Admins' jsmith")

        group_dn = get_dn(self.client, self.domain_dumper, args[0])
        if not group_dn:
            raise Exception("Group not found: %s" % args[0])

        user_dn = get_dn(self.client, self.domain_dumper, args[1])
        if not user_dn:
            raise Exception("User not found: %s" % args[1])

        print_info("Adding %s to %s" % (args[1], args[0]))
        self.client.modify(group_dn, {'member': [(ldap3.MODIFY_ADD, [user_dn])]})
        check_result(self.client, "User added to group")

    do_add_user_to_group = do_add_group_member  # 向后兼容别名

    # ── remove_group_member ───────────────────────────────────
    def do_remove_group_member(self, line):
        """remove_group_member <group> <user> — 从组中移除成员"""
        args = parse_args(line, 2, 2, "remove_group_member 'Domain Admins' jsmith")

        group_dn = get_dn(self.client, self.domain_dumper, args[0])
        if not group_dn:
            raise Exception("Group not found: %s" % args[0])

        user_dn = get_dn(self.client, self.domain_dumper, args[1])
        if not user_dn:
            raise Exception("User not found: %s" % args[1])

        print_info("Removing %s from %s" % (args[1], args[0]))
        self.client.modify(group_dn, {'member': [(ldap3.MODIFY_DELETE, [user_dn])]})
        check_result(self.client, "User removed from group")

    # ── nested_groups ─────────────────────────────────────────
    def do_nested_groups(self, line):
        """nested_groups <group> — 查看嵌套组"""
        args = parse_args(line, 1, 1, "nested_groups 'Domain Admins'")
        dn = get_dn(self.client, self.domain_dumper, args[0])
        if not dn:
            raise Exception("Group not found: %s" % args[0])

        # 查询属于该组的所有组 (仅组对象)
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(&(objectClass=group)(memberof:%s:=%s))' % (LDAP_MATCHING_RULE_IN_CHAIN, escape_filter_chars(dn)),
            attributes=['sAMAccountName', 'distinguishedName'],
        )
        if entries:
            print_success("Found %d nested group(s)" % len(entries))
            for entry in entries:
                print_found("%s (%s)" % (entry['sAMAccountName'].value, entry.entry_dn))
        else:
            print_warn("No nested groups found")
