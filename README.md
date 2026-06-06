# 🐚 CliShell

## 📋 1. 项目概述

CliShell 是一个基于 impacket 的交互式 LDAP Shell，专为 Active Directory 渗透测试设计，拓展自impacket的ldap-shell，满足了攻防项目中的大多数域渗透的大部分信息搜集&&ACL滥用场景，使用分页查询在大型域环境中也可以正常运行，相关功能见命令列表

---

## 🗂️ 2. 代码结构

```
CliShell/
├── 🚀 clishell.py                  # 入口: 参数解析、LDAP 连接、启动 Shell
├── utils/
│   ├── __init__.py                 # 包初始化
│   ├── 🧠 clishell_core.py         # 主 Shell 类 (继承 16 个 Mixin + cmd.Cmd)
│   ├── 🔧 helpers.py               # 共用工具函数 (LDAP 查询、ACL、分页、显示)
│   ├── 🎨 ui.py                    # UI 组件 (Banner、帮助、彩色消息前缀)
│   └── mixins/                     # 命令模块 (每个 Mixin 对应一个功能分类)
│       ├── 💻 computer.py          # 机器管理 (4 命令)
│       ├── 👤 user.py              # 用户管理 (4 命令)
│       ├── 👥 group.py             # 组管理 (9 命令)
│       ├── 📁 ou.py                # OU 管理 (6 命令)
│       ├── 🌐 domain_info.py       # 域/森林/信任/站点/子网/RODC (10 命令)
│       ├── 🔗 dns.py               # DNS 查询 (4 命令)
│       ├── 📬 exchange.py          # Exchange 信息 (1 命令)
│       ├── 📜 adcs.py              # ADCS/WSUS (2 命令)
│       ├── 🔄 delegation.py        # 委派/Shadow Credentials (6 命令)
│       ├── 🔐 acl.py               # ACL 审计与授权 (34 命令)
│       ├── 📡 session.py           # 会话/登录 (4 命令, RPC)
│       ├── 👑 privilege.py         # 特权用户审计 (1 命令)
│       ├── 📋 gpo.py               # GPO 管理 (5 命令)
│       ├── 🔍 search.py            # 通用搜索 (6 命令)
│       ├── 🎯 assessment.py        # 安全评估 (3 命令)
│       ├── ℹ️ basic_info.py         # 域基本信息 (1 命令)
│       └── 🔌 connection.py        # 连接管理 (3 命令)
└── README.md
```

---

## 📦 3. 安装

```bash
pip install impacket ldap3 ldapdomaindump colorama
```

---

## 🚀 4. 使用

```bash
python3 clishell.py domain.local/username:password@dc_ip
python3 clishell.py domain.local/username@dc_ip -hashes aad3b435b51404eeaad3b435b51404ee:nthash
python3 clishell.py domain.local/username:password@dc_ip -ldaps
```

![image-20260606183500186](/Users/chun/coding/CliShell/assets/image-20260606183500186.png)

查看域的基本信息，包括机器/域用户数量、MAQ等信息，如图所示

![image-20260606183712618](/Users/chun/coding/CliShell/assets/image-20260606183712618.png)

查看域内的委派情况，以及配置rbcd功能

![](/Users/chun/coding/CliShell/assets/image-20260606183826801.png)

> ACL相关功能测试

参考bloodhound中的ACL，基本集成了其中的大多数权限的查询以及分配，`find_interesting_acl`可以查看所有的可以被利用的ACL(我这里过滤了域内的默认ACL)

![image-20260606184946132](/Users/chun/coding/CliShell/assets/image-20260606184946132.png)

![image-20260606184058767](/Users/chun/coding/CliShell/assets/image-20260606184058767.png)

dcsync也正常

![image-20260606184209142](/Users/chun/coding/CliShell/assets/image-20260606184209142.png)

> find_privileged_users

查询特殊组下的成员（backup operators组等等）以及adminCount=1的用户

![image-20260606185619473](/Users/chun/coding/CliShell/assets/image-20260606185619473.png)

> find_sessions administrator

基于445+rpc查询会话（拿下域管后定位特定用户）

![image-20260606183626219](/Users/chun/coding/CliShell/assets/image-20260606183626219.png)

![image-20260606190120603](/Users/chun/coding/CliShell/assets/image-20260606190120603.png)

> add_user|add_computer功能

基于ldaps来添加用户无SPN的账号，主要是在打nopac/adcs的时候，大多数工具都是走445+sarm来添加账号，当445关闭的时候通过ldaps是最快最方便的添加账号的方法

> dump功能，将一些信息保存到本地

![image-20260606190602488](/Users/chun/coding/CliShell/assets/image-20260606190602488.png)

## ⌨️ 5. 命令列表

| 分类 | 命令 |
|------|------|
| 💻 **机器管理** | `add_computer`, `delete_computer`, `move_computer`, `get_computer` |
| 👤 **用户管理** | `add_user`, `delete_user`, `get_user`, `unlock_user` |
| 👥 **组管理** | `add_group`, `delete_group`, `get_group`, `list_groups`, `group_members`, `group_owner`, `add_group_member`, `remove_group_member`, `nested_groups` |
| 📁 **OU 管理** | `list_ous`, `get_ou`, `create_ou`, `delete_ou`, `move_object`, `ou_acl` |
| 🌐 **域 / 信任** | `domain_trusts`, `domain_sites`, `domain_subnets`, `forest_info`, `forest_domains`, `get_rodc` |
| 🔗 **DNS** | `dns_zones`, `dns_records`, `dns_hosts`, `dns_servers` |
| 📬 **Exchange** | `get_exchange` |
| 📜 **ADCS / WSUS** | `get_adcs`, `get_wsus` |
| 🔄 **委派** | `find_delegation`, `set_rbcd`, `remove_rbcd`, `find_shadowcredentials`, `add_shadowcredential`, `remove_shadowcredential` |
| 🔍 **ACL 查询** | `object_acl`, `find_interesting_acl`, `find_generic_all`, `find_generic_write`, `find_write_owner`, `find_write_dacl`, `find_all_extended_rights`, `find_force_change_password`, `find_add_member`, `find_add_self`, `find_read_laps`, `find_read_gmsa`, `find_gp_link`, `find_write_spn`, `find_write_account_restrictions`, `find_sid_history`, `find_owns` |
| ✏️ **ACL 授权** | `grant_control`, `grant_generic_write`, `grant_write_dacl`, `grant_write_owner`, `grant_all_extended_rights`, `grant_force_change_password`, `grant_add_member`, `grant_add_self`, `grant_write_spn`, `grant_write_account_restrictions`, `grant_read_laps`, `grant_read_gmsa`, `set_dcsync`, `get_dcsync`, `remove_dcsync`, `revoke_ace`, `write_gpo_dacl` |
| 📡 **会话 / 登录** | `computer_sessions` [RPC], `user_sessions` [RPC], `find_sessions` [RPC], `active_users` |
| 👑 **特权审计** | `find_privileged_users` |
| 🤝 **信任 / 森林** | `trusts`, `trust_map`, `external_trusts`, `forest_trusts` |
| 📋 **GPO** | `gpo_list`, `gpo_info`, `gpo_links`, `gpo_permissions`, `gpo_security_filtering` |
| 🔎 **搜索** | `search`, `search_user`, `search_group`, `search_computer`, `search_ou`, `search_spn` |
| 🎯 **安全评估** | `find_kerberoastable`, `find_preauth_disabled`, `find_gpp_passwords` |
| 🔌 **连接** | `get_basic_info`, `start_tls`, `dump`, `get_laps_password`, `exit` |
