import argparse
import sys
import logging
import ldap3
import ldapdomaindump
import ssl

from impacket import LOG
from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from utils.clishell_core import CliShell


class CliShellLauncher:
    def __init__(self, domain, baseDN, username, password, address, options):
        self.domain = domain
        self.baseDN = baseDN
        self.username = username
        self.password = password
        self.lmhash = ''
        self.nthash = ''
        self.address = address
        self.ldaps_flag = ''

        if options.ldaps == True:
            self.ldaps_flag = True

        if options.hashes is not None:
            self.lmhash, self.nthash = options.hashes.split(':')
            if self.lmhash == "":
                self.lmhash = "aad3b435b51404eeaad3b435b51404ee"

    def ldap_connection(self, tls_version):
        user_withDomain = '%s\\%s' % (self.domain, self.username)
        if tls_version is not None:
            use_ssl = True
            port = 636
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version, ciphers='DEFAULT:@SECLEVEL=0')
        else:
            use_ssl = False
            port = 389
            tls = None
        ldap_server = ldap3.Server(self.address, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
        if self.nthash != "":
            ldap_session = ldap3.Connection(ldap_server, user=user_withDomain, password=self.lmhash + ":" + self.nthash, authentication=ldap3.NTLM, auto_bind=True)
        else:
            ldap_session = ldap3.Connection(ldap_server, user=user_withDomain, password=self.password, authentication=ldap3.NTLM, auto_bind=True)
        return ldap_server, ldap_session

    # For ldap3 with tls mode(only for ldap3).
    # Picked function from rbcd.py
    def ldap_sessions(self):
        if self.ldaps_flag == True:
            try:
                return self.ldap_connection(tls_version=ssl.PROTOCOL_TLSv1_2)
            except ldap3.core.exceptions.LDAPSocketOpenError:
                return self.ldap_connection(tls_version=ssl.PROTOCOL_TLSv1)
        else:
            return self.ldap_connection(tls_version=None)

    def start_shell(self, ldap_server, ldap_session):
        domainDumpConfig = ldapdomaindump.domainDumpConfig()
        domainDumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, domainDumpConfig)
        shell = CliShell(
            self.baseDN, domainDumper, ldap_session,
            username=self.username, dc_address=self.address,
            password=self.password, lmhash=self.lmhash, nthash=self.nthash,
        )
        shell.cmdloop()

if __name__ == '__main__':
    logger.init()

    parser = argparse.ArgumentParser(add_help=True, description="CliShell — Interactive LDAP shell for AD penetration testing")

    parser.add_argument('target', action='store', help='[domain/][username[:password]@]<address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help="don't ask for password")
    group.add_argument('-ldaps', action='store_true', help='Connect LDAP server over LDAPS, port 636')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    try:
        if domain == '':
            print("[-] Domain need to be specify.")
            sys.exit(0)

        if password == '' and username != '' and options.hashes is None and options.no_pass is False:
            from getpass import getpass
            password = getpass("Password:")

        baseDN = ''
        domainParts = domain.split('.')
        for i in domainParts:
            baseDN += 'dc=%s,' % i
        baseDN = baseDN[:-1]

        launcher = CliShellLauncher(domain, baseDN, username, password, address, options)
        ldap_server, ldap_session = launcher.ldap_sessions()

        proto = 'LDAPS' if options.ldaps else 'LDAP'
        from colorama import Fore, Style
        print(Fore.GREEN + Style.BRIGHT + "[+]" + Style.RESET_ALL
              + Fore.WHITE + " Authentication OK — bound to %s via %s" % (baseDN, proto))
        print(Fore.GREEN + Style.BRIGHT + "[+]" + Style.RESET_ALL
              + Fore.WHITE + " Server: %s  User: %s\\%s" % (address, domain, username))

        launcher.start_shell(ldap_server, ldap_session)

    except (Exception, KeyboardInterrupt) as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
    sys.exit(0)
