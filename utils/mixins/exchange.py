#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exchange Mixin — Exchange 综合信息收集 (1 个命令)
"""

import socket

from utils.ui import print_info, print_success, print_found, print_warn, print_header

# ═══════════════════════════════════════════════════════════
#  Exchange 版本 → 名称 + 已知高危 CVE
#  注: 仅列出各版本已知公开 CVE，实际是否受影响取决于补丁状态
# ═══════════════════════════════════════════════════════════

EXCHANGE_VERSIONS = {
    '14.0': ('Exchange 2010 RTM', [
        'CVE-2020-0688 (Crypto Static Key RCE)',
        'CVE-2021-26855 (ProxyLogon SSRF)',
    ]),
    '14.1': ('Exchange 2010 SP1', [
        'CVE-2020-0688',
        'CVE-2021-26855 (ProxyLogon)',
    ]),
    '14.2': ('Exchange 2010 SP2', [
        'CVE-2020-0688',
        'CVE-2021-26855 (ProxyLogon)',
    ]),
    '14.3': ('Exchange 2010 SP3', [
        'CVE-2020-0688',
        'CVE-2021-26855 (ProxyLogon)',
    ]),
    '15.0': ('Exchange 2013', [
        'CVE-2020-0688 (Crypto Static Key RCE)',
        'CVE-2021-26855 (ProxyLogon SSRF)',
        'CVE-2021-26858 (ProxyLogon RCE)',
        'CVE-2021-27065 (ProxyLogon RCE)',
        'CVE-2021-34473 (ProxyShell Auth Bypass)',
    ]),
    '15.1': ('Exchange 2016', [
        'CVE-2020-0688 (Crypto Static Key RCE)',
        'CVE-2021-26855 (ProxyLogon SSRF)',
        'CVE-2021-26858 (ProxyLogon RCE)',
        'CVE-2021-27065 (ProxyLogon RCE)',
        'CVE-2021-34473 (ProxyShell Auth Bypass)',
        'CVE-2021-34523 (ProxyShell PrivEsc)',
        'CVE-2021-31207 (ProxyShell RCE)',
        'CVE-2022-41040 (ProxyNotShell SSRF)',
        'CVE-2022-41082 (ProxyNotShell RCE)',
        'CVE-2024-21410 (Privilege Escalation)',
    ]),
    '15.2': ('Exchange 2019', [
        'CVE-2020-0688 (Crypto Static Key RCE)',
        'CVE-2021-26855 (ProxyLogon SSRF)',
        'CVE-2021-26858 (ProxyLogon RCE)',
        'CVE-2021-27065 (ProxyLogon RCE)',
        'CVE-2021-34473 (ProxyShell Auth Bypass)',
        'CVE-2021-34523 (ProxyShell PrivEsc)',
        'CVE-2021-31207 (ProxyShell RCE)',
        'CVE-2022-41040 (ProxyNotShell SSRF)',
        'CVE-2022-41082 (ProxyNotShell RCE)',
        'CVE-2023-21709 (OWA EoP)',
        'CVE-2024-21410 (Privilege Escalation)',
    ]),
}

# 服务器角色位映射
ROLE_MAP = {
    2: 'Mailbox',
    4: 'ClientAccess',
    20: 'HubTransport',
    64: 'UnifiedMessaging',
    38: 'Mailbox+HT+CAS',
    16: 'Edge',
}


class ExchangeMixin:
    """Exchange 信息收集命令集"""

    # ── get_exchange ──────────────────────────────────────────
    def do_get_exchange(self, line):
        """get_exchange — Exchange 综合信息 (服务器/IP/版本/CVE/URL)"""
        print_info("Searching Exchange servers...")

        # ── 1. Exchange 服务器 ────────────────────────────────
        self.client.search(
            self.domain_dumper.root,
            '(objectClass=msExchExchangeServer)',
            attributes=['cn', 'distinguishedName', 'msExchVersion',
                        'networkAddress', 'msExchCurrentServerRoles'],
        )
        entries = self.client.entries

        if not entries:
            # 备用：通过 Exchange SPN 查找
            self.client.search(
                self.domain_dumper.root,
                '(servicePrincipalName=exchangeMDB*)',
                attributes=['sAMAccountName', 'dNSHostName', 'distinguishedName'],
            )
            entries = self.client.entries

        if not entries:
            print_warn("No Exchange servers found")
            return

        print_success("Found %d Exchange server(s)" % len(entries))

        # ── 2. 逐服务器输出：IP / 版本 / CVE ─────────────────
        for entry in entries:
            # 名称
            name = None
            for attr in ('cn', 'sAMAccountName'):
                try:
                    name = entry[attr].value
                    if name:
                        break
                except (KeyError, Exception):
                    pass
            if not name:
                name = entry.entry_dn

            # IP
            ip = self._get_exchange_ip(entry, name)

            # 版本
            ver_raw = 'Unknown'
            try:
                ver_raw = str(entry['msExchVersion'].value or 'Unknown')
            except (KeyError, Exception):
                pass
            ver_short = '.'.join(ver_raw.split('.')[:2]) if ver_raw != 'Unknown' else ''
            ver_name, cves = EXCHANGE_VERSIONS.get(
                ver_short, ('Unknown (%s)' % ver_raw, []))

            # 角色
            role = ''
            try:
                role_val = entry['msExchCurrentServerRoles'].value
                role = ROLE_MAP.get(role_val, 'Role=%s' % role_val)
            except (KeyError, Exception):
                pass

            # 输出
            print_header("Server: %s" % name)
            print_info("  IP:      %s" % ip)
            if role:
                print_info("  Role:    %s" % role)
            print_info("  Version: %s" % ver_name)
            print_info("  Build:   %s" % ver_raw)

            if cves:
                print_warn("  Known CVEs (if unpatched):")
                for cve in cves:
                    print_found("    %s" % cve)

        # ── 3. OWA / ECP 等虚拟目录 URL ──────────────────────
        self._print_exchange_urls()

    # ── 内部辅助 ──────────────────────────────────────────────

    def _get_exchange_ip(self, entry, name):
        """从 networkAddress 或 DNS 解析获取 IP"""
        try:
            for addr in entry['networkAddress'].values:
                if 'ncacn_ip_tcp:' in str(addr).lower():
                    return str(addr).split(':')[-1]
        except (KeyError, Exception):
            pass
        try:
            return socket.gethostbyname(name)
        except Exception:
            return '(unresolved)'

    def _print_exchange_urls(self):
        """查找 OWA / ECP / OAB 等虚拟目录 URL"""
        config_dn = self._get_config_dn()
        if not config_dn:
            return

        print_header("Virtual Directories")
        try:
            self.client.search(
                config_dn,
                '(objectClass=msExchVirtualDirectory)',
                attributes=['cn', 'internalUrl', 'externalUrl'],
            )
            for entry in self.client.entries:
                cn = ''
                try:
                    cn = entry['cn'].value or ''
                except (KeyError, Exception):
                    pass
                internal = ''
                external = ''
                try:
                    internal = entry['internalUrl'].value or ''
                except (KeyError, Exception):
                    pass
                try:
                    external = entry['externalUrl'].value or ''
                except (KeyError, Exception):
                    pass
                if not (internal or external):
                    continue
                print_found("  %-20s %s" % (cn, internal or '(no internal)'))
                if external:
                    print_info("  %-20s %s (external)" % ('', external))
        except Exception:
            print_warn("  Unable to query virtual directories")
