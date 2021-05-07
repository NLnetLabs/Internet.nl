# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import ast
import os
from enum import Enum
from enumfields import EnumField, EnumIntegerField
from enumfields import Enum as LabelEnum
from uuid import uuid4 as uuid

from django.core.exceptions import SuspiciousFileOperation
from django.db import models, transaction
from django.utils import timezone


class DnssecStatus(Enum):
    insecure = 0
    secure = 1
    bogus = 2
    servfail = 3
    dnserror = 4


class DaneStatus(Enum):
    validated = 0
    failed = 1
    none = 2
    none_bogus = 3


class ForcedHttpsStatus(Enum):
    bad = 0
    good = 1
    no_http = 2


class OcspStatus(Enum):
    ok = 0
    good = 1
    not_trusted = 2


class ZeroRttStatus(Enum):
    bad = 0
    good = 1
    na = 2


class KexHashFuncStatus(Enum):
    bad = 0
    good = 1
    unknown = 2


class CipherOrderStatus(Enum):
    bad = 0
    good = 1
    not_prescribed = 2
    not_seclevel = 3
    na = 4  # Don't care about order; only GOOD ciphers.


class MxStatus(LabelEnum):
    has_mx = 0
    no_mx = 1
    no_null_mx = 2
    invalid_null_mx = 3
    null_mx = 4


def conn_test_id():
    num_tries = 0
    while num_tries <= 6:
        new_uuid = uuid().hex
        try:
            ConnectionTest.objects.get(test_id=new_uuid)
        except ConnectionTest.DoesNotExist:
            return new_uuid
        num_tries += 1
    raise Exception("Not able to get random id")


def batch_request_id():
    num_tries = 0
    while num_tries <= 6:
        new_uuid = uuid().hex
        try:
            BatchRequest.objects.get(request_id=new_uuid)
        except BatchRequest.DoesNotExist:
            return new_uuid
        num_tries += 1
    raise Exception("Not able to get random id")


class ListField(models.TextField):
    def __init__(self, *args, **kwargs):
        super(ListField, self).__init__(*args, **kwargs)

    def from_db_value(self, value, expression, connection, context):
        if value is None:
            return value
        return ast.literal_eval(value)

    def to_python(self, value):
        if not value:
            value = []
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            return value
        return ast.literal_eval(value)

    def get_prep_value(self, value):
        if value is None:
            return value
        return str(value)

    def value_to_string(self, obj):
        value = self._get_val_from_obj(obj)
        return self.get_db_prep_value(value)


class BaseTestModel(models.Model):
    """
    Base class for the models.

    """

    class Meta:
        abstract = True

    def totalscore(self, score_fields):
        if self.score is not None:
            return self.score

        totalscore = 0
        for score_field in score_fields:
            s = getattr(self, score_field)
            if type(s) is int:
                totalscore += s
        self.score = totalscore
        self.save()
        return totalscore

    def details(self, probe):
        return getattr(self, probe.reportfield)

    def details_set(self, probe):
        return [("", "", self.details(probe))]


###
# Domain test
##
class ConnectionTest(BaseTestModel):
    report = ListField(default="")
    reportdnssec = ListField(default="")
    test_id = models.CharField(
        unique=True, db_index=True, max_length=32, default=conn_test_id)
    timestamp = models.DateTimeField(auto_now_add=True)

    ipv4_addr = models.CharField(max_length=16, default="")
    ipv4_owner = models.CharField(max_length=255, default="")
    ipv4_origin_as = models.ForeignKey(
        'ASRecord', null=True, related_name='ipv4_connection_tests')
    ipv4_reverse = models.CharField(max_length=255, default="")

    ipv6_addr = models.CharField(max_length=40, default="")
    ipv6_owner = models.CharField(max_length=255, default="")
    ipv6_origin_as = models.ForeignKey(
        'ASRecord', null=True, related_name='ipv6_connection_tests')
    ipv6_reverse = models.CharField(max_length=255, default="")
    aaaa_ipv6 = models.BooleanField(default=False)
    addr_ipv6 = models.BooleanField(default=False)

    resolv_ipv6 = models.BooleanField(default=False)
    slaac_without_privext = models.BooleanField(default=False)
    dnssec_val = models.BooleanField(default=False)

    score_ipv6 = models.IntegerField(null=True)
    score_ipv6_max = models.IntegerField(null=True)
    score_dnssec = models.IntegerField(null=True)
    score_dnssec_max = models.IntegerField(null=True)

    finished = models.BooleanField(default=False)

    def totalscore(self, probe):
        score = 0
        if probe.scorename == "ipv6":
            if self.score_ipv6 is None:
                score = self.ipv6score()
            else:
                score = self.score_ipv6

        else:
            if self.score_dnssec is None:
                score = self.dnssecscore()
            else:
                score = self.score_dnssec

        return score

    def ipv6score(self):
        score = 0
        if self.aaaa_ipv6:
            score += 60
        if self.addr_ipv6:
            score += 20
        if self.resolv_ipv6:
            score += 20

        self.score_ipv6 = score
        self.save()

        return score

    def dnssecscore(self):
        score = 0
        if self.dnssec_val:
            score = 100
        else:
            score = 0

        self.score_dnssec = score
        self.save()

        return score

    def __dir__(self):
        return [
            'report', 'reportdnssec', 'test_id', 'timestamp', 'ipv4_addr',
            'ipv4_owner', 'ipv4_origin_as', 'ipv4_reverse', 'ipv6_addr',
            'ipv6_owner', 'ipv6_origin_as', 'ipv6_reverse', 'aaaa_ipv6',
            'addr_ipv6', 'resolv_ipv6', 'slaac_without_privext',
            'dnssec_val', 'score_ipv6', 'score_ipv6_max', 'score_dnssec',
            'score_dnssec_max', 'finished'
        ]


class Resolver(models.Model):
    connectiontest = models.ForeignKey(ConnectionTest)
    address = models.CharField(max_length=40)
    owner = models.CharField(max_length=255)
    origin_as = models.ForeignKey(
        'ASRecord', null=True, related_name='resolvers')
    reverse = models.CharField(max_length=255)

    def __dir__(self):
        return ['connectiontest', 'address', 'owner', 'origin_as', 'reverse']


class ASRecord(models.Model):
    number = models.PositiveIntegerField(unique=True)
    description = models.CharField(max_length=255)

    def __dir__(self):
        return ['number', 'description']


###
# Domain test
##


# IPV6
class DomainTestIpv6(BaseTestModel):
    timestamp = models.DateTimeField(auto_now_add=True)
    domain = models.CharField(max_length=255)
    report = ListField(default="")
    web_simhash_distance = models.IntegerField(null=True)
    web_simhash_score = models.IntegerField(null=True)
    web_score = models.IntegerField(null=True)
    mx_score = models.IntegerField(null=True)
    ns_score = models.IntegerField(null=True)
    score = models.IntegerField(null=True)
    max_score = models.IntegerField(null=True)

    def __dir__(self):
        return [
            'timestamp', 'domain', 'report', 'web_simhash_distance',
            'web_simhash_score', 'web_score', 'mx_score', 'ns_score', 'score',
            'max_score'
        ]


class IPv6TestDomain(models.Model):
    domain = models.CharField(max_length=255)
    v6_good = ListField(default=[])
    v6_bad = ListField(default=[])
    v4_good = ListField(default=[])
    v4_bad = ListField(default=[])
    score = models.IntegerField(null=True)

    def __dir__(self):
        return ['domain', 'v6_good', 'v6_bad', 'v4_good', 'v4_bad', 'score']

    class Meta:
        abstract = True


class WebDomain(IPv6TestDomain):
    domaintestipv6 = models.ForeignKey(
        DomainTestIpv6, null=True, related_name='webdomains')

    def __dir__(self):
        return super(WebDomain, self).__dir__().extend([
            'domaintestipv6',
        ])


class DomainServersModel(models.Model):
    """
    A domain can have multiple servers (ie. IP adresses, mailservers).
    Use this class to map server results to domain.

    """
    class Meta:
        abstract = True

    domain = models.CharField(max_length=255, default="")
    report = ListField(default="")
    score = models.IntegerField(null=True)
    max_score = models.IntegerField(null=True)

    def totalscore(self, score_fields, testset, mailtest=False):
        if self.score is not None:
            return self.score

        if len(testset) == 0:
            total = 0
        else:
            total = min(
                [result.totalscore(score_fields) for result in testset])
        self.score = total
        self.save()
        return self.score

    def details_set(self, probe, testset):
        return [('', '', self.report)]

    def details(self, probe):
        return self.details_set(probe)

    def __dir__(self):
        return ['domain', 'report', 'score', 'max_score']


class MailTestTls(DomainServersModel):
    mx_status = EnumIntegerField(MxStatus, null=True)

    def totalscore(self, score_fields):
        tests_subset = self.testset.all()
        return super(MailTestTls, self).totalscore(
            score_fields, tests_subset, mailtest=True)

    def details_set(self, probe):
        return super(MailTestTls, self).details_set(probe, self.testset)

    def __dir__(self):
        return ['mx_status'] + super(MailTestTls, self).__dir__()


class MailTestDnssec(DomainServersModel):
    mx_status = EnumIntegerField(MxStatus, null=True)

    def totalscore(self, score_fields):
        return super(MailTestDnssec, self).totalscore(
            score_fields, self.testset.all(), mailtest=True)

    def details_set(self, probe):
        return super(MailTestDnssec, self).details_set(probe, self.testset)

    def __dir__(self):
        return ['mx_status'] + super(MailTestDnssec, self).__dir__()


# DNSSEC
class DomainTestDnssec(BaseTestModel):
    timestamp = models.DateTimeField(auto_now_add=True)
    domain = models.CharField(max_length=255)
    report = ListField(default="")
    status = EnumField(DnssecStatus, default=DnssecStatus.insecure)
    log = models.TextField(default="", null=True)
    score = models.IntegerField(null=True)
    max_score = models.IntegerField(null=True)
    maildomain = models.ForeignKey(
        MailTestDnssec, null=True, related_name="testset")

    def __dir__(self):
        return [
            'timestamp', 'domain', 'report', 'status', 'log', 'score',
            'max_score', 'maildomain'
        ]


class WebTestTls(DomainServersModel):
    def totalscore(self, score_fields):
        tests_subset = self.webtestset.all()
        return super(WebTestTls, self).totalscore(score_fields, tests_subset)

    def details_set(self, probe):
        return super(WebTestTls, self).details_set(probe, self.webtestset)


class DomainTestTls(BaseTestModel):
    timestamp = models.DateTimeField(auto_now_add=True)
    domain = models.CharField(max_length=255, default="")
    report = ListField(default="")
    port = models.IntegerField(null=True)
    maildomain = models.ForeignKey(
        MailTestTls, null=True, related_name="testset")
    webdomain = models.ForeignKey(
        WebTestTls, null=True, related_name="webtestset")
    server_reachable = models.NullBooleanField(default=True)
    tls_enabled = models.NullBooleanField(default=False)
    tls_enabled_score = models.IntegerField(null=True)
    could_not_test_smtp_starttls = models.BooleanField(default=False)

    # DANE
    dane_log = models.TextField(default="", null=True)
    dane_score = models.IntegerField(null=True)
    dane_status = EnumField(DaneStatus, default=DaneStatus.none)
    dane_records = ListField(default=[])
    dane_rollover = models.BooleanField(default=False)

    # TLS connection
    dh_param = models.CharField(max_length=255, default="", null=True)
    ecdh_param = models.CharField(max_length=255, default="", null=True)
    fs_bad = ListField(null=True)
    fs_phase_out = ListField(null=True)
    fs_score = models.IntegerField(null=True)

    ciphers_bad = ListField(null=True)
    ciphers_phase_out = ListField(null=True)
    ciphers_score = models.IntegerField(null=True)

    cipher_order = EnumField(CipherOrderStatus, default=CipherOrderStatus.bad)
    cipher_order_violation = ListField(null=True)
    cipher_order_score = models.IntegerField(null=True)

    protocols_bad = ListField(null=True)
    protocols_good = ListField(null=True)
    protocols_phase_out = ListField(null=True)
    protocols_score = models.IntegerField(null=True)

    compression = models.NullBooleanField(default=False)
    compression_score = models.IntegerField(null=True)
    secure_reneg = models.NullBooleanField(default=False)
    secure_reneg_score = models.IntegerField(null=True)
    client_reneg = models.NullBooleanField(default=False)
    client_reneg_score = models.IntegerField(null=True)

    zero_rtt = EnumField(ZeroRttStatus, default=ZeroRttStatus.bad)
    zero_rtt_score = models.IntegerField(null=True)

    ocsp_stapling = EnumField(OcspStatus, default=OcspStatus.ok)
    ocsp_stapling_score = models.IntegerField(null=True)

    kex_hash_func = EnumField(KexHashFuncStatus, default=KexHashFuncStatus.bad)
    kex_hash_func_score = models.IntegerField(null=True)

    forced_https = EnumField(ForcedHttpsStatus, default=ForcedHttpsStatus.bad)
    forced_https_score = models.IntegerField(null=True)

    # HTTP headers
    http_compression_enabled = models.NullBooleanField(default=False)
    http_compression_score = models.IntegerField(null=True)

    hsts_enabled = models.NullBooleanField(default=False)
    hsts_policies = ListField(default=[])
    hsts_score = models.IntegerField(null=True)

    # Cert-chain
    cert_chain = ListField(null=True)

    cert_trusted = models.IntegerField(null=True)
    cert_trusted_score = models.IntegerField(null=True)

    cert_pubkey_bad = ListField(null=True)
    cert_pubkey_phase_out = ListField(null=True)
    cert_pubkey_score = models.IntegerField(null=True)

    cert_signature_bad = ListField(null=True)
    cert_signature_score = models.IntegerField(null=True)

    cert_hostmatch_bad = ListField(null=True)
    cert_hostmatch_score = models.IntegerField(null=True)

    score = models.IntegerField(null=True)

    def __dir__(self):
        return [
            'timestamp', 'domain', 'report', 'port', 'maildomain', 'webdomain',
            'server_reachable', 'tls_enabled', 'tls_enabled_score',
            'could_not_test_smtp_starttls', 'dane_log', 'dane_score',
            'dane_status', 'dh_param', 'ecdh_param', 'fs_bad', 'fs_phase_out',
            'fs_score', 'ciphers_bad', 'ciphers_phase_out', 'ciphers_score',
            'cipher_order', 'cipher_order_violation', 'cipher_order_score',
            'protocols_bad', 'protocols_phase_out', 'protocols_score',
            'compression', 'compression_score', 'secure_reneg',
            'secure_reneg_score', 'client_reneg', 'client_reneg_score',
            'zero_rtt', 'zero_rtt_score', 'ocsp_stapling',
            'ocsp_stapling_score', 'kex_hash_func', 'kex_hash_func_score',
            'forced_https', 'forced_https_score', 'http_compression_enabled',
            'http_compression_score', 'hsts_enabled', 'hsts_policies',
            'hsts_score', 'cert_chain', 'cert_trusted', 'cert_trusted_score',
            'cert_pubkey_bad', 'cert_pubkey_phase_out', 'cert_pubkey_score',
            'cert_signature_bad', 'cert_signature_score', 'cert_hostmatch_bad',
            'cert_hostmatch_score', 'score', 'protocols_good',
        ]

    def get_web_api_details(self):
        return {
            'dane_status': self.dane_status.name,
            'dane_records': self.dane_records,
            'kex_params_bad': self.fs_bad,
            'kex_params_phase_out': self.fs_phase_out,
            'ciphers_bad': self.ciphers_bad,
            'ciphers_phase_out': self.ciphers_phase_out,
            'cipher_order': self.cipher_order.name,
            'cipher_order_violation': self.cipher_order_violation,
            'protocols_bad': self.protocols_bad,
            'protocols_phase_out': self.protocols_phase_out,
            'compression': self.compression,
            'secure_reneg': self.secure_reneg,
            'client_reneg': self.client_reneg,
            'zero_rtt': self.zero_rtt.name,
            'ocsp_stapling': self.ocsp_stapling.name,
            'kex_hash_func': self.kex_hash_func.name,
            'https_redirect': self.forced_https.name,
            'http_compression': self.http_compression_enabled,
            'hsts': self.hsts_enabled,
            'hsts_policies': self.hsts_policies,
            'cert_chain': self.cert_chain,
            'cert_trusted': self.cert_trusted,
            'cert_pubkey_bad': self.cert_pubkey_bad,
            'cert_pubkey_phase_out': self.cert_pubkey_phase_out,
            'cert_signature_bad': self.cert_signature_bad,
            'cert_hostmatch_bad': self.cert_hostmatch_bad,
        }

    def get_mail_api_details(self):
        return {
            'dane_status': self.dane_status.name,
            'dane_records': self.dane_records,
            'dane_rollover': self.dane_rollover,
            'kex_params_bad': self.fs_bad,
            'kex_params_phase_out': self.fs_phase_out,
            'ciphers_bad': self.ciphers_bad,
            'ciphers_phase_out': self.ciphers_phase_out,
            'cipher_order': self.cipher_order.name,
            'cipher_order_violation': self.cipher_order_violation,
            'protocols_bad': self.protocols_bad,
            'protocols_phase_out': self.protocols_phase_out,
            'compression': self.compression,
            'secure_reneg': self.secure_reneg,
            'client_reneg': self.client_reneg,
            'zero_rtt': self.zero_rtt.name,
            'kex_hash_func': self.kex_hash_func.name,
            'cert_chain': self.cert_chain,
            'cert_trusted': self.cert_trusted,
            'cert_pubkey_bad': self.cert_pubkey_bad,
            'cert_pubkey_phase_out': self.cert_pubkey_phase_out,
            'cert_signature_bad': self.cert_signature_bad,
            'cert_hostmatch_bad': self.cert_hostmatch_bad,
        }


class WebTestAppsecpriv(DomainServersModel):
    def totalscore(self, score_fields):
        tests_subset = self.webtestset.all()
        return super(WebTestAppsecpriv, self).totalscore(
            score_fields, tests_subset)

    def details_set(self, probe):
        return super(WebTestAppsecpriv, self).details_set(
            probe, self.webtestset)


class DomainTestAppsecpriv(BaseTestModel):
    timestamp = models.DateTimeField(auto_now_add=True)
    domain = models.CharField(max_length=255, default="")
    report = ListField(default="")
    webdomain = models.ForeignKey(
        WebTestAppsecpriv, null=True, related_name="webtestset")
    server_reachable = models.BooleanField(default=True)
    score = models.IntegerField(null=True)

    x_frame_options_enabled = models.NullBooleanField(default=False)
    x_frame_options_values = ListField(default=[])
    x_frame_options_score = models.IntegerField(null=True)

    x_xss_protection_enabled = models.NullBooleanField(default=False)
    x_xss_protection_values = ListField(default=[])
    x_xss_protection_score = models.IntegerField(null=True)

    referrer_policy_enabled = models.NullBooleanField(default=False)
    referrer_policy_values = ListField(default=[])
    referrer_policy_score = models.IntegerField(null=True)

    content_security_policy_enabled = models.NullBooleanField(default=False)
    content_security_policy_values = ListField(default=[])
    content_security_policy_score = models.IntegerField(null=True)

    x_content_type_options_enabled = models.NullBooleanField(default=False)
    x_content_type_options_values = ListField(default=[])
    x_content_type_options_score = models.IntegerField(null=True)

    def __dir__(self):
        return [
            'timestamp', 'domain', 'report', 'webdomain', 'server_reachable',
            'score', 'x_frame_options_enabled', 'x_frame_options_values',
            'x_frame_options_score', 'x_xss_protection_enabled',
            'x_xss_protection_values', 'x_xss_protection_score',
            'referrer_policy_enabled', 'referrer_policy_values',
            'referrer_policy_score', 'content_security_policy_enabled',
            'content_security_policy_values', 'content_security_policy_score',
            'x_content_type_options_enabled', 'x_content_type_options_values',
            'x_content_type_options_score',
        ]

    def get_web_api_details(self):
        return {
            'content_security_policy_enabled': self.content_security_policy_enabled,
            'content_security_policy_values': self.content_security_policy_values,
            'referrer_policy_enabled': self.referrer_policy_enabled,
            'referrer_policy_values': self.referrer_policy_values,
            'x_content_type_options_enabled': self.x_content_type_options_enabled,
            'x_content_type_options_values': self.x_content_type_options_values,
            'x_frame_options_enabled': self.x_frame_options_enabled,
            'x_frame_options_values': self.x_frame_options_values,
            # TODO: to be removed in the future.
            #'x_xss_protection_enabled': self.x_xss_protection_enabled,
            #'x_xss_protection_values': self.x_xss_protection_values,
        }


class DomainTestReport(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    domain = models.CharField(max_length=255, default="")
    registrar = models.CharField(max_length=255, default="")
    score = models.IntegerField(null=True)
    ipv6 = models.ForeignKey(DomainTestIpv6, null=True)
    dnssec = models.ForeignKey(DomainTestDnssec, null=True)
    tls = models.ForeignKey(WebTestTls, null=True)
    appsecpriv = models.ForeignKey(WebTestAppsecpriv, null=True)

    def __dir__(self):
        return [
            'timestamp', 'domain', 'registrar', 'score', 'ipv6', 'dnssec',
            'tls', 'appsecpriv',
        ]


###
# Mail test
##


# IPv6
class MailTestIpv6(BaseTestModel):
    timestamp = models.DateTimeField(auto_now_add=True)
    domain = models.CharField(max_length=255)
    report = ListField(default="")
    mx_score = models.IntegerField(null=True)
    ns_score = models.IntegerField(null=True)
    score = models.IntegerField(null=True)
    max_score = models.IntegerField(null=True)
    mx_status = EnumIntegerField(MxStatus, null=True)

    def __dir__(self):
        return [
            'timestamp', 'domain', 'report', 'mx_score', 'ns_score', 'score',
            'max_score', 'mx_status'
        ]


class NsDomain(IPv6TestDomain):
    domaintestipv6 = models.ForeignKey(
        DomainTestIpv6, null=True, related_name='nsdomains')
    mailtestipv6 = models.ForeignKey(
        MailTestIpv6, null=True, related_name='nsdomains')

    def __dir__(self):
        return super(NsDomain, self).__dir__().extend([
            'domaintestipv6',
            'mailtestipv6',
        ])


class MxDomain(IPv6TestDomain):
    mailtestipv6 = models.ForeignKey(
        MailTestIpv6, null=True, related_name='mxdomains')

    def __dir__(self):
        return super(MxDomain, self).__dir__().extend([
            'mailtestipv6',
        ])


class DmarcPolicyStatus(LabelEnum):
    valid = 0
    invalid_syntax = 1
    invalid_p_sp = 2
    invalid_external = 3


class SpfPolicyStatus(LabelEnum):
    valid = 0
    invalid_syntax = 1
    max_dns_lookups = 2
    invalid_all = 3
    invalid_include = 4
    invalid_redirect = 5


# DKIM/DMARC/SPF
class MailTestAuth(BaseTestModel):
    timestamp = models.DateTimeField(auto_now_add=True)
    domain = models.CharField(max_length=255)
    report = ListField(default="")
    dkim_score = models.IntegerField(null=True)
    dkim_available = models.BooleanField(default=False)
    dmarc_score = models.IntegerField(null=True)
    dmarc_available = models.BooleanField(default=False)
    dmarc_record = ListField(default=[])
    dmarc_record_org_domain = models.CharField(max_length=255, null=True)
    dmarc_policy_status = EnumIntegerField(DmarcPolicyStatus, null=True)
    dmarc_policy_score = models.IntegerField(null=True)
    spf_score = models.IntegerField(null=True)
    spf_available = models.BooleanField(default=False)
    spf_record = ListField(default=[])
    spf_policy_status = EnumIntegerField(SpfPolicyStatus, null=True)
    spf_policy_score = models.IntegerField(null=True)
    spf_policy_records = ListField(null=True)
    score = models.IntegerField(null=True)
    max_score = models.IntegerField(null=True)

    def __dir__(self):
        return [
            'timestamp', 'domain', 'report', 'dkim_score', 'dkim_available',
            'dmarc_score', 'dmarc_available', 'dmarc_record',
            'dmarc_record_org_domain', 'dmarc_policy_status',
            'dmarc_policy_score', 'spf_score', 'spf_available', 'spf_record',
            'spf_policy_status', 'spf_policy_score', 'spf_policy_records',
            'score', 'max_score'
        ]


class MailTestReport(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    domain = models.CharField(max_length=255, default="")
    registrar = models.CharField(max_length=255, default="")
    score = models.IntegerField(null=True)
    ipv6 = models.ForeignKey(MailTestIpv6, null=True)
    dnssec = models.ForeignKey(MailTestDnssec, null=True)
    auth = models.ForeignKey(MailTestAuth, null=True)
    tls = models.ForeignKey(MailTestTls, null=True)

    def __dir__(self):
        return [
            'timestamp', 'domain', 'registrar', 'score', 'ipv6', 'dnssec',
            'auth', 'tls'
        ]


class BatchUser(models.Model):
    """
    Users allowed to run batch tests.

    .. note:: Must be in sync with the web authorization scheme.

    """
    username = models.CharField(unique=True, max_length=255)
    name = models.CharField(max_length=255)
    organization = models.CharField(max_length=255)
    email = models.EmailField(max_length=255)

    def __dir__(self):
        return ['username', 'name', 'organization', 'email']

    @transaction.atomic
    def delete_related_data(self, delete_self=False):
        for request in BatchRequest.objects.filter(user=self).all():
            # Delete the request's related data but not the request itself.
            # They will be deleted by the DB when the user gets deleted later.
            request.delete_related_data()

        if delete_self:
            self.delete()


class BatchRequestType(LabelEnum):
    web = 0
    mail = 1


class BatchRequestStatus(LabelEnum):
    # Initial statuses (0-9)
    registering = 0

    # In process statuses (10-19)
    live = 10
    running = 11  # No domains in the waiting status.

    # Good final statuses (20-29)
    done = 20

    # Bad final statuses (30-39)
    error = 38
    cancelled = 39


class BatchRequest(models.Model):
    """
    The main table for batch requests.

    """
    user = models.ForeignKey(BatchUser, related_name="batch_requests")
    name = models.CharField(max_length=255)
    submit_date = models.DateTimeField(auto_now_add=True)
    finished_date = models.DateTimeField(null=True)
    type = EnumIntegerField(BatchRequestType)
    status = EnumIntegerField(
        BatchRequestStatus,
        default=BatchRequestStatus.registering,
        db_index=True)
    request_id = models.CharField(
        unique=True, db_index=True, max_length=32, default=batch_request_id)
    report_file = models.FileField(upload_to='batch_results/')
    report_technical_file = models.FileField(upload_to='batch_results/', null=True)

    def __dir__(self):
        return [
            'user', 'name', 'submit_date', 'finished_date', 'type', 'status',
            'request_id', 'report_file', 'report_technical_file'
        ]

    def _api_status(self):
        if self.status == BatchRequestStatus.registering:
            return "registering"
        elif self.status in (BatchRequestStatus.live, BatchRequestStatus.running):
            return "running"
        elif self.status == BatchRequestStatus.error:
            return "error"
        elif self.status == BatchRequestStatus.done:
            if self.has_report_file():
                return "done"
            return "generating"
        elif self.status == BatchRequestStatus.cancelled:
            return "cancelled"
        return "-"

    def has_report_file(self):
        return (self.report_file
                and os.path.isfile(self.report_file.path)
                and self.report_technical_file
                and os.path.isfile(self.report_technical_file.path))

    def get_report_file(self, technical=False):
        if technical:
            return self.report_technical_file
        return self.report_file

    def to_api_dict(self):
        finished_date = self.finished_date
        if finished_date:
            finished_date = finished_date.isoformat()
        return dict(
            name=self.name,
            submit_date=self.submit_date.isoformat(),
            finished_date=finished_date,
            request_type=self.type.label.lower(),
            status=self._api_status(),
            request_id=self.request_id)

    @transaction.atomic
    def delete_related_data(self, delete_self=False):
        # Remove the generated files.
        try:
            self.report_file.delete()
            self.report_technical_file.delete()
        except (IOError, SuspiciousFileOperation):
            pass

        # Remove the related BatchWebTest and BatchMailTest entries.
        batch_webtest_ids = {
            d.webtest_id for d in
            BatchDomain.objects.filter(batch_request=self).all()}
        batch_mailtest_ids = {
            d.mailtest_id for d in
            BatchDomain.objects.filter(batch_request=self).all()}
        BatchWebTest.objects.filter(id__in=batch_webtest_ids).delete()
        BatchMailTest.objects.filter(id__in=batch_mailtest_ids).delete()

        if delete_self:
            self.delete()


class BatchDomainStatus(LabelEnum):
    # Inital statuses (0-9)
    waiting = 0

    # In process statuses (10-19)
    running = 10

    # Good final statuses (20-29)
    done = 20

    # Bad final statuses (30-39)
    error = 38
    cancelled = 39


class BatchDomain(models.Model):
    """
    Table to hold the domains being registered for batch testing.

    """
    domain = models.CharField(max_length=255, default="")
    batch_request = models.ForeignKey(BatchRequest, related_name="domains")
    status = EnumIntegerField(
        BatchDomainStatus, default=BatchDomainStatus.waiting, db_index=True)
    status_changed = models.DateTimeField(default=timezone.now)
    webtest = models.ForeignKey('BatchWebTest', null=True)
    mailtest = models.ForeignKey('BatchMailTest', null=True)

    def get_batch_test(self):
        if self.webtest:
            return self.webtest
        return self.mailtest

    def __dir__(self):
        return [
            'domain', 'batch_result', 'status', 'status_changed', 'webtest',
            'mailtest'
        ]


class BatchTestStatus(LabelEnum):
    """
    SHOULD be the same as BatchDomainStatus. It is redefined here because
    Python does not allow for Enum subclassing.

    """
    # Inital statuses (0-9)
    waiting = 0

    # In process statuses (10-19)
    running = 10

    # Good final statuses (20-29)
    done = 20

    # Bad final statuses (30-39)
    error = 38
    cancelled = 39


class BatchWebTest(models.Model):
    """
    Entries that point to the actual subtest's results and report for the
    web tests.

    """
    report = models.ForeignKey(DomainTestReport, null=True)
    ipv6 = models.ForeignKey(DomainTestIpv6, null=True)
    ipv6_status = EnumIntegerField(
        BatchTestStatus, default=BatchTestStatus.waiting)
    ipv6_errors = models.PositiveSmallIntegerField(default=0)
    dnssec = models.ForeignKey(DomainTestDnssec, null=True)
    dnssec_status = EnumIntegerField(
        BatchTestStatus, default=BatchTestStatus.waiting)
    dnssec_errors = models.PositiveSmallIntegerField(default=0)
    tls = models.ForeignKey(WebTestTls, null=True)
    tls_status = EnumIntegerField(
        BatchTestStatus, default=BatchTestStatus.waiting)
    tls_errors = models.PositiveSmallIntegerField(default=0)
    appsecpriv = models.ForeignKey(WebTestAppsecpriv, null=True)
    appsecpriv_status = EnumIntegerField(
        BatchTestStatus, default=BatchTestStatus.waiting)
    appsecpriv_errors = models.PositiveSmallIntegerField(default=0)

    def __dir__(self):
        return [
            'report', 'ipv6', 'ipv6_status', 'ipv6_errors', 'dnssec',
            'dnssec_status', 'dnssec_errors', 'tls', 'tls_status',
            'tls_errors', 'appsecpriv', 'appsecpriv_status',
            'appsecpriv_errors',
        ]


class BatchMailTest(models.Model):
    """
    Entries that point to the actual subtest's results and report for the
    mail tests.

    """
    report = models.ForeignKey(MailTestReport, null=True)
    ipv6 = models.ForeignKey(MailTestIpv6, null=True)
    ipv6_status = EnumIntegerField(
        BatchTestStatus, default=BatchTestStatus.waiting)
    ipv6_errors = models.PositiveSmallIntegerField(default=0)
    dnssec = models.ForeignKey(MailTestDnssec, null=True)
    dnssec_status = EnumIntegerField(
        BatchTestStatus, default=BatchTestStatus.waiting)
    dnssec_errors = models.PositiveSmallIntegerField(default=0)
    auth = models.ForeignKey(MailTestAuth, null=True)
    auth_status = EnumIntegerField(
        BatchTestStatus, default=BatchTestStatus.waiting)
    auth_errors = models.PositiveSmallIntegerField(default=0)
    tls = models.ForeignKey(MailTestTls, null=True)
    tls_status = EnumIntegerField(
        BatchTestStatus, default=BatchTestStatus.waiting)
    tls_errors = models.PositiveSmallIntegerField(default=0)

    def __dir__(self):
        return [
            'report', 'ipv6', 'ipv6_status', 'ipv6_errors', 'dnssec',
            'dnssec_status', 'dnssec_errors', 'auth', 'auth_status',
            'auth_errors', 'tls', 'tls_status', 'tls_errors'
        ]


class AutoConfOption(Enum):
    DATED_REPORT_ID_THRESHOLD_WEB = 'DATED_REPORT_ID_THRESHOLD_WEB'
    DATED_REPORT_ID_THRESHOLD_MAIL = 'DATED_REPORT_ID_THRESHOLD_MAIL'


class AutoConf(models.Model):
    """
    Various configuration options that need to be applied automatically
    (e.g., through migrations).

    Any available options are defined in AutoConfOption above.

    """
    name = EnumField(AutoConfOption, max_length=255, primary_key=True)
    value = models.CharField(max_length=255, default=None)

    @classmethod
    def get_option(cls, option, default=None):
        try:
            return cls.objects.get(name=option).value
        except cls.DoesNotExist:
            return default

    @classmethod
    def set_option(cls, option, value):
        try:
            op = cls.objects.get(name=option)
            op.value = value
        except cls.DoesNotExist:
            op = cls(name=option, value=value)
        op.save()

    def __dir__(self):
        return ['name', 'value']
