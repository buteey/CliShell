#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OU Management Mixin — 组织单位管理命令 (6 个)
"""

import ldap3
from ldap3.protocol.microsoft import security_descriptor_control

from utils.ui import print_info, print_success, print_found, print_warn
from utils.helpers import (
    parse_args, check_result,
    display_entry, display_entries, paged_search,
)


class OUMixin:
    """OU Management 命令集"""

    # ── list_ous ──────────────────────────────────────────────
    def do_list_ous(self, line):
        """list_ous — 枚举所有 OU"""
        print_info("Enumerating OUs...")
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=organizationalUnit)',
            attributes=['name', 'distinguishedName', 'description'],
        )
        print_success("Found %d OU(s)" % len(entries))
        display_entries(entries, ['name', 'distinguishedName', 'description'])

    # ── get_ou ────────────────────────────────────────────────
    def do_get_ou(self, line):
        """get_ou <ou_name> — 查看 OU 详情"""
        args = parse_args(line, 1, 1, "get_ou 'Domain Controllers'")

        from ldap3.utils.conv import escape_filter_chars
        self.client.search(
            self.domain_dumper.root,
            '(&(objectClass=organizationalUnit)(name=%s))' % escape_filter_chars(args[0]),
            attributes=['*'],
        )
        if not self.client.entries:
            raise Exception("OU not found: %s" % args[0])
        display_entry(self.client.entries[0])

    # ── create_ou ─────────────────────────────────────────────
    def do_create_ou(self, line):
        """create_ou <ou_name> [parent_dn] — 创建 OU"""
        args = parse_args(line, 1, 2, "create_ou MyOU [DC=corp,DC=local]")

        ou_name = args[0]
        parent = args[1] if len(args) > 1 else self.domain_dumper.root
        ou_dn = 'OU=%s,%s' % (ou_name, parent)

        print_info("Creating OU: %s" % ou_dn)
        res = self.client.add(ou_dn, ['top', 'organizationalUnit'], {'ou': ou_name})
        if not res:
            raise Exception("Failed: %s" % self.client.result.get('description', ''))
        print_success("OU created: %s" % ou_dn)

    # ── delete_ou ─────────────────────────────────────────────
    def do_delete_ou(self, line):
        """delete_ou <ou_dn> — 删除 OU (必须为空)"""
        args = parse_args(line, 1, 1, "delete_ou OU=MyOU,DC=corp,DC=local")

        dn = args[0]
        if '=' not in dn:
            # 如果只给了名称，尝试查找
            from ldap3.utils.conv import escape_filter_chars
            self.client.search(
                self.domain_dumper.root,
                '(&(objectClass=organizationalUnit)(name=%s))' % escape_filter_chars(dn),
                attributes=['distinguishedName'],
            )
            if not self.client.entries:
                raise Exception("OU not found: %s" % dn)
            dn = self.client.entries[0].entry_dn

        print_info("Deleting OU: %s" % dn)
        self.client.delete(dn)
        check_result(self.client, "OU deleted")

    # ── move_object ───────────────────────────────────────────
    def do_move_object(self, line):
        """move_object <object_dn> <target_ou> — 移动对象到 OU"""
        args = parse_args(line, 2, 2, "move_object CN=jsmith,CN=Users,DC=corp,DC=local OU=NewOU,DC=corp,DC=local")

        object_dn = args[0]
        target_ou = args[1]

        # 提取 RDN 用于 modify_dn
        rdn = object_dn.split(',')[0]
        rdn_attr, _, rdn_val = rdn.partition('=')

        print_info("Moving %s → %s" % (object_dn, target_ou))
        self.client.modify_dn(object_dn, '%s=%s' % (rdn_attr, rdn_val), new_superior=target_ou)
        check_result(self.client, "Object moved successfully")

    # ── ou_acl ────────────────────────────────────────────────
    def do_ou_acl(self, line):
        """ou_acl <ou_name> — 查看 OU 的 ACL"""
        args = parse_args(line, 1, 1, "ou_acl 'Domain Controllers'")

        from ldap3.utils.conv import escape_filter_chars
        controls = security_descriptor_control(sdflags=0x04)
        self.client.search(
            self.domain_dumper.root,
            '(&(objectClass=organizationalUnit)(name=%s))' % escape_filter_chars(args[0]),
            attributes=['nTSecurityDescriptor'],
            controls=controls,
        )
        if not self.client.entries:
            raise Exception("OU not found: %s" % args[0])

        from impacket.ldap import ldaptypes
        entry = self.client.entries[0]
        try:
            sd_data = entry['nTSecurityDescriptor'].raw_values[0]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)

            print_info("OU: %s" % entry.entry_dn)
            print_info("Owner: %s" % sd['OwnerSid'].formatCanonical())
            print_info("DACL ACEs:")

            for i, ace in enumerate(sd['Dacl'].aces):
                try:
                    sid = ace['Ace']['Sid'].formatCanonical()
                    mask = ace['Ace']['Mask']['Mask']
                    ace_type = ace['AceType']
                    print_found("  [%d] Type=%s SID=%s Mask=0x%08x" % (i, ace_type, sid, mask))
                except Exception:
                    print_found("  [%d] (unable to parse ACE)" % i)
        except (IndexError, KeyError):
            print_warn("Unable to read security descriptor")
