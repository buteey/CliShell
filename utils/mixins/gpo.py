#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GPO Mixin — Group Policy Object 命令 (5 个)
"""

from ldap3.utils.conv import escape_filter_chars

from utils.ui import print_info, print_success, print_found, print_warn
from utils.helpers import parse_args, display_entry, paged_search


class GPOMixin:
    """GPO 命令集"""

    # ── gpo_list ──────────────────────────────────────────────
    def do_gpo_list(self, line):
        """gpo_list — GPO 列表"""
        print_info("Enumerating GPOs...")
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=groupPolicyContainer)',
            attributes=['cn', 'displayName', 'distinguishedName', 'gPCFileSysPath', 'versionNumber'],
        )
        print_success("Found %d GPO(s)" % len(entries))
        for entry in entries:
            display_name = entry['displayName'].value or entry['cn'].value
            path = entry['gPCFileSysPath'].value or ''
            version = entry['versionNumber'].value or 0
            print_found("%s (v%s) — %s" % (display_name, version, path))

    # ── gpo_info ──────────────────────────────────────────────
    def do_gpo_info(self, line):
        """gpo_info <gpo_name_or_guid> — GPO 详细信息"""
        args = parse_args(line, 1, 1, "gpo_info '{31B2F340-016D-11D2-945F-00C04FB984F9}'")

        search_val = args[0]
        # 支持按 GUID 或 displayName 查找
        if search_val.startswith('{'):
            filt = '(cn=%s)' % escape_filter_chars(search_val)
        else:
            filt = '(displayName=%s)' % escape_filter_chars(search_val)

        self.client.search(
            self.domain_dumper.root,
            '(&(objectClass=groupPolicyContainer)%s)' % filt,
            attributes=['*'],
        )
        if not self.client.entries:
            raise Exception("GPO not found: %s" % args[0])
        display_entry(self.client.entries[0])

    # ── gpo_links ─────────────────────────────────────────────
    def do_gpo_links(self, line):
        """gpo_links — GPO 链接关系"""
        print_info("Searching for GPO links...")

        # GPO 链接存储在 OU/Domain 的 gPLink 属性中
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(gPLink=*)',
            attributes=['cn', 'distinguishedName', 'gPLink', 'gPOptions'],
        )
        print_success("Found %d object(s) with GPO links" % len(entries))

        for entry in entries:
            gplink = entry['gPLink'].value or ''
            gpoptions = entry['gPOptions'].value or 0

            print_found("Object: %s" % entry.entry_dn)
            if gpoptions == 2:
                print_warn("  Block inheritance enabled!")

            # 解析 gPLink 格式: [LDAP://CN={GUID},CN=Policies,...;0][...;1]
            import re
            links = re.findall(r'\[LDAP://([^;]+);(\d+)\]', gplink)
            for link_dn, options in links:
                # 提取 GPO GUID
                guid_match = re.search(r'\{[^}]+\}', link_dn)
                guid = guid_match.group(0) if guid_match else link_dn

                opt_flags = int(options)
                enforced = "ENFORCED" if opt_flags & 2 else ""
                disabled = "DISABLED" if opt_flags & 1 else ""
                flags_str = ', '.join(filter(None, [enforced, disabled]))

                print_found("  → %s %s" % (guid, ('(%s)' % flags_str) if flags_str else ''))

    # ── gpo_permissions ───────────────────────────────────────
    def do_gpo_permissions(self, line):
        """gpo_permissions — GPO 权限"""
        print_info("Scanning GPO permissions...")
        from ldap3.protocol.microsoft import security_descriptor_control

        controls = security_descriptor_control(sdflags=0x04)

        from impacket.ldap import ldaptypes
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=groupPolicyContainer)',
            attributes=['cn', 'displayName', 'nTSecurityDescriptor'],
            controls=controls,
        )
        for entry in entries:
            name = entry['displayName'].value or entry['cn'].value
            try:
                sd_data = entry['nTSecurityDescriptor'].raw_values[0]
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
                for ace in sd['Dacl'].aces:
                    try:
                        sid = ace['Ace']['Sid'].formatCanonical()
                        mask = ace['Ace']['Mask']['Mask']
                        # 只显示高权限 ACE (写/完全控制)
                        if mask & 0x00040000 or mask & 0x00080000 or mask & 0x00020000:
                            print_found("%s — %s has WriteDacl/WriteOwner/Write (0x%08x)" % (
                                name, sid, mask))
                    except Exception:
                        continue
            except (IndexError, KeyError):
                continue

    # ── gpo_security_filtering ────────────────────────────────
    def do_gpo_security_filtering(self, line):
        """gpo_security_filtering — GPO 安全筛选"""
        print_info("Querying GPO security filtering...")

        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=groupPolicyContainer)',
            attributes=['cn', 'displayName', 'gPLink'],
        )

        for entry in entries:
            name = entry['displayName'].value or entry['cn'].value
            print_found("GPO: %s" % name)
            # 安全筛选通过 GPO 对象的 DACL 实现
            # Authenticated Users 具有 "Apply Group Policy" 权限
            # 自定义筛选会修改 DACL 中的 ACE
            print_info("  (Check DACL for 'Apply Group Policy' permissions)")
