#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Computer Management Mixin — 机器账户管理命令 (4 个)
"""

import string
import random
from ldap3.utils.conv import escape_filter_chars
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM

from utils.ui import print_info, print_success, print_error, print_found, print_warn
from utils.helpers import (
    parse_args, is_ldaps, require_ldaps, check_result,
    get_dn, get_entry, get_domain_name, ad_timestamp_to_str,
    LDAP_MATCHING_RULE_IN_CHAIN, UAC,
    paged_search,
)


class ComputerMixin:
    """Computer Management 命令集"""

    # ── add_computer ──────────────────────────────────────────
    def do_add_computer(self, line):
        """add_computer <computer> [password] [nospns] — 创建机器账户 (需要 LDAPS)"""
        args = parse_args(line, 1, 3, "add_computer MYSERVER$ [password] [nospns]")

        require_ldaps(self.client)

        computer_name = args[0]
        if not computer_name.endswith('$'):
            computer_name += '$'

        # 密码处理：未指定则随机生成
        password = ""
        nospns = False
        if len(args) == 1:
            password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))
        elif len(args) == 2:
            if args[1] == "nospns":
                password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))
                nospns = True
            else:
                password = args[1]
        elif len(args) == 3:
            password = args[1] if args[1] != "nospns" else ''.join(
                random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))
            nospns = (args[2] == "nospns" or args[1] == "nospns")

        domain_dn = self.domain_dumper.root
        domain = get_domain_name(domain_dn)
        hostname = computer_name[:-1]  # 去掉 $

        # SPN 列表
        if nospns:
            spns = ['HOST/%s.%s' % (hostname, domain)]
        else:
            spns = [
                'HOST/%s' % hostname,
                'HOST/%s.%s' % (hostname, domain),
                'RestrictedKrbHost/%s' % hostname,
                'RestrictedKrbHost/%s.%s' % (hostname, domain),
            ]

        computer_dn = "CN=%s,CN=Computers,%s" % (hostname, domain_dn)
        print_info("Creating computer: %s" % computer_dn)

        ucd = {
            'dnsHostName': '%s.%s' % (hostname, domain),
            'userAccountControl': 4096,  # WORKSTATION_TRUST_ACCOUNT
            'servicePrincipalName': spns,
            'sAMAccountName': computer_name,
            'unicodePwd': '"{}"'.format(password).encode('utf-16-le'),
        }

        res = self.client.add(computer_dn, ['top', 'person', 'organizationalPerson', 'user', 'computer'], ucd)
        if not res:
            if self.client.result['result'] == RESULT_UNWILLING_TO_PERFORM:
                print_error("Server denied the operation (likely needs LDAPS or machine quota exceeded).")
            else:
                print_error("Failed: %s" % self.client.result.get('description', ''))
        else:
            print_success("Created: %s / Password: %s" % (computer_name, password))

    # ── delete_computer ───────────────────────────────────────
    def do_delete_computer(self, line):
        """delete_computer <computer> — 删除机器账户"""
        args = parse_args(line, 1, 1, "delete_computer MYSERVER$")

        computer_name = args[0]
        if not computer_name.endswith('$'):
            computer_name += '$'

        dn = get_dn(self.client, self.domain_dumper, computer_name)
        if not dn:
            raise Exception("Computer not found: %s" % computer_name)

        print_info("Deleting: %s (%s)" % (computer_name, dn))
        self.client.delete(dn)
        check_result(self.client, "Deleted %s" % computer_name)

    # ── move_computer ─────────────────────────────────────────
    def do_move_computer(self, line):
        """move_computer <computer> <ou_dn> — 移动机器到指定 OU"""
        args = parse_args(line, 2, 2, "move_computer MYSERVER$ OU=Servers,DC=corp,DC=local")

        computer_name = args[0]
        if not computer_name.endswith('$'):
            computer_name += '$'

        dn = get_dn(self.client, self.domain_dumper, computer_name)
        if not dn:
            raise Exception("Computer not found: %s" % computer_name)

        # 解析目标 OU 的 RDN，构造新 DN
        rdn = dn.split(',')[0]  # e.g. CN=MYSERVER
        new_dn = '%s,%s' % (rdn, args[1])

        print_info("Moving: %s → %s" % (dn, new_dn))
        # 使用 ldap3 的 modify_dn 实现 "移动" (修改 parent)
        rdn_part = rdn.split('=', 1)[1]  # MYSERVER
        self.client.modify_dn(dn, 'CN=%s' % rdn_part, new_superior=args[1])
        check_result(self.client, "Moved successfully")

    # ── get_computer ──────────────────────────────────────────
    def do_get_computer(self, line):
        """get_computer <computer> — 查看机器完整详情 (含 SPN/组/Owner/登录)"""
        from ldap3.protocol.microsoft import security_descriptor_control
        from impacket.ldap import ldaptypes

        args = parse_args(line, 1, 1, "get_computer MYSERVER$")
        computer_name = args[0]
        if not computer_name.endswith('$'):
            computer_name += '$'

        entry = get_entry(self.client, self.domain_dumper, computer_name)
        if not entry:
            raise Exception("Computer not found: %s" % computer_name)

        # ── 安全属性读取 ──
        def _attr(name, default=''):
            try:
                v = entry[name].value
                return v if v is not None else default
            except (KeyError, IndexError):
                return default

        def _fmt_ts(ts):
            if not ts:
                return 'Never'
            s = ad_timestamp_to_str(ts)
            if '1601' in s:
                return 'Never'
            s = str(s)
            if '+' in s:
                s = s[:s.rfind('+')]
            if '.' in s:
                s = s[:s.rfind('.')]
            return s.strip()

        dn = entry.entry_dn
        sam = _attr('sAMAccountName', '?')
        dns_host = _attr('dNSHostName', '')
        os_name = _attr('operatingSystem', '')
        os_ver = _attr('operatingSystemVersion', '')
        uac_val = _attr('userAccountControl', 0) or 0
        when_created = _attr('whenCreated', '')
        when_changed = _attr('whenChanged', '')

        # UAC 标志
        flags = []
        if uac_val & UAC['ACCOUNTDISABLE']:
            flags.append('DISABLED')
        if uac_val & UAC['TRUSTED_FOR_DELEGATION']:
            flags.append('TRUSTED_FOR_DELEGATION')
        if uac_val & UAC['NOT_DELEGATED']:
            flags.append('NOT_DELEGATED')
        enabled = 'No' if uac_val & UAC['ACCOUNTDISABLE'] else 'Yes'
        flags_str = ', '.join(flags) if flags else 'NORMAL'

        # ── 横排主表 ──
        os_display = os_name + (' ' + os_ver if os_ver else '')
        header = ['Computer', 'Enabled', 'UAC', 'OS', 'lastLogon', 'pwdLastSet']
        row = [
            sam,
            enabled,
            flags_str,
            os_display or 'Unknown',
            _fmt_ts(_attr('lastLogon', 0) or 0),
            _fmt_ts(_attr('pwdLastSet', 0) or 0),
        ]

        col_lens = [max(len(h), len(r)) for h, r in zip(header, row)]
        fmt = ' '.join(['{:<%d}' % w for w in col_lens])

        print()
        print(fmt.format(*header))
        print(' '.join(['-' * w for w in col_lens]))
        print(fmt.format(*row))

        # ── 附加信息 ──

        # DN / DNS
        print()
        print_found("DN:   %s" % dn)
        if dns_host:
            print_found("DNS:  %s" % dns_host)
        print_found("SID:  %s" % str(_attr('objectSid', '')))

        # SPNs
        try:
            spns = entry['servicePrincipalName'].values
            if spns:
                print()
                for spn in spns:
                    print_found("SPN:  %s" % spn)
        except (KeyError, IndexError):
            pass

        # Groups (递归)
        try:
            group_entries = paged_search(
                self.client, self.domain_dumper.root,
                '(member:%s:=%s)' % (LDAP_MATCHING_RULE_IN_CHAIN, escape_filter_chars(dn)),
                attributes=['sAMAccountName'],
            )
            if group_entries:
                groups = [g['sAMAccountName'].value for g in group_entries if g['sAMAccountName'].value]
                print()
                print_info("Groups (%d): %s" % (len(groups), ', '.join(groups)))
        except Exception:
            pass

        # Owner
        try:
            controls = security_descriptor_control(sdflags=0x01)
            entry_sd = get_entry(self.client, self.domain_dumper, computer_name,
                                 ['nTSecurityDescriptor'], controls=controls)
            if entry_sd:
                sd_data = entry_sd['nTSecurityDescriptor'].raw_values[0]
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
                owner_sid = sd['OwnerSid'].formatCanonical()
                owner_name = self._resolve_sid(owner_sid)
                owner_display = '%s (%s)' % (owner_name, owner_sid) if owner_name else owner_sid
                print()
                print_found("Owner:  %s" % owner_display)
        except (IndexError, KeyError):
            pass

        # Creator
        try:
            entry_creator = get_entry(self.client, self.domain_dumper, computer_name,
                                      ['mS-DS-CreatorSID'])
            if entry_creator:
                creator_sid_raw = entry_creator['mS-DS-CreatorSID'].value
                if creator_sid_raw is not None:
                    if isinstance(creator_sid_raw, bytes):
                        from impacket.ldap.ldaptypes import LDAP_SID
                        sid_obj = LDAP_SID()
                        sid_obj.fromString(creator_sid_raw)
                        creator_sid = sid_obj.formatCanonical()
                    else:
                        creator_sid = str(creator_sid_raw)
                    creator_name = self._resolve_sid(creator_sid)
                    creator_display = '%s (%s)' % (creator_name, creator_sid) if creator_name else creator_sid
                    print_found("Creator: %s" % creator_display)
        except (KeyError, IndexError, AttributeError):
            pass
