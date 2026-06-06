#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Privilege Mixin — 高权限账户发现命令 (1 个)
综合审计：高权限组成员 + AdminCount=1 + Exchange 特权组
"""

from ldap3.utils.conv import escape_filter_chars

from utils.ui import print_info, print_success, print_found, print_warn
from utils.helpers import (
    LDAP_MATCHING_RULE_IN_CHAIN,
    paged_search,
)


# 待审计的高权限组列表
_PRIV_GROUPS = [
    'Administrators',
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Backup Operators',
    'Account Operators',
    # 远程访问组
    'Remote Desktop Users',
    'Remote Management Users',
    'Network Configuration Operators',
    # Exchange 特权组
    'Exchange Windows Permissions',
    'Organization Management',
]


class PrivilegeMixin:
    """Privilege / 高权限账户命令集"""

    # ── find_privileged_users ───────────────────────────────────
    def do_find_privileged_users(self, line):
        """find_privileged_users — 综合高权限账户审计 (特权组 + AdminCount + Exchange)"""
        print_info("Auditing privileged users...")

        # user_dn → {sam, groups:[], admin_count:bool, disabled:bool}
        users = {}

        # ── 1. 逐组递归查询成员 ───────────────────────────────
        for group_name in _PRIV_GROUPS:
            self._collect_group_members(group_name, users)

        # ── 2. AdminCount=1 账户 ────────────────────────────────
        admin_count_entries = paged_search(
            self.client, self.domain_dumper.root,
            '(&(objectClass=user)(!(objectClass=computer))(adminCount=1))',
            attributes=['sAMAccountName', 'distinguishedName', 'userAccountControl'],
        )
        for entry in admin_count_entries:
            dn = entry.entry_dn
            sam = entry['sAMAccountName'].value
            uac = entry['userAccountControl'].value or 0
            if dn not in users:
                users[dn] = {
                    'sam': sam,
                    'groups': [],
                    'admin_count': True,
                    'disabled': bool(uac & 0x0002),
                }
            else:
                users[dn]['admin_count'] = True

        if not users:
            print_warn("No privileged users found")
            return

        # ── 3. 横排表格输出 ────────────────────────────────────
        sorted_users = sorted(users.values(), key=lambda u: (-len(u['groups']), u['sam']))

        header = ['Username', 'Disabled', 'adminCnt', 'Groups']
        rows = []
        for u in sorted_users:
            groups_str = ', '.join(u['groups']) if u['groups'] else '-'
            if u['admin_count'] and 'AdminCount=1' not in groups_str:
                groups_str += ' [AdminCount=1]' if groups_str != '-' else '[AdminCount=1]'
            rows.append([
                u['sam'],
                'Yes' if u['disabled'] else 'No',
                '1' if u['admin_count'] else '0',
                groups_str,
            ])

        col_lens = [max(len(header[i]), max(len(r[i]) for r in rows)) for i in range(len(header))]
        fmt = ' '.join(['{:<%d}' % w for w in col_lens])

        print()
        print(fmt.format(*header))
        print(' '.join(['-' * w for w in col_lens]))
        for r in rows:
            print(fmt.format(*r))

    # ── 内部辅助 ──────────────────────────────────────────────
    def _collect_group_members(self, group_name, users):
        """递归查找指定组的所有成员，结果合并到 users dict"""
        # 找到组的 DN
        self.client.search(
            self.domain_dumper.root,
            '(&(objectClass=group)(sAMAccountName=%s))' % escape_filter_chars(group_name),
            attributes=['distinguishedName'],
        )
        if not self.client.entries:
            return  # 组不存在（如 Exchange 未安装），跳过

        group_dn = self.client.entries[0].entry_dn

        # LDAP_MATCHING_RULE_IN_CHAIN 递归查所有成员
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(memberof:%s:=%s)' % (LDAP_MATCHING_RULE_IN_CHAIN, escape_filter_chars(group_dn)),
            attributes=['sAMAccountName', 'distinguishedName', 'userAccountControl'],
        )
        for entry in entries:
            dn = entry.entry_dn
            sam = entry['sAMAccountName'].value
            uac = entry['userAccountControl'].value or 0
            if dn not in users:
                users[dn] = {
                    'sam': sam,
                    'groups': [group_name],
                    'admin_count': False,
                    'disabled': bool(uac & 0x0002),
                }
            else:
                if group_name not in users[dn]['groups']:
                    users[dn]['groups'].append(group_name)
