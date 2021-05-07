# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from binascii import hexlify
import errno
import http.client
import logging
import socket
import ssl
import time
from enum import Enum
from timeit import default_timer as timer

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from cryptography.x509 import load_pem_x509_certificate, NameOID, ExtensionOID
from cryptography.x509 import ExtensionNotFound, SignatureAlgorithmOID, DNSName
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePublicKey
from cryptography.hazmat.backends.openssl.dh import _DHPublicKey
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.backends.openssl.dsa import _DSAPublicKey
from cryptography.hazmat.primitives import hashes
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from itertools import product
from nassl import _nassl
from nassl.ssl_client import OpenSslVersionEnum
from nassl.ocsp_response import OcspResponseNotTrustedError

from . import SetupUnboundContext
from .dispatcher import check_registry, post_callback_hook
from .http_headers import HeaderCheckerContentEncoding, http_headers_check
from .http_headers import HeaderCheckerStrictTransportSecurity
from .shared import resolve_dane, get_mail_servers_mxstatus
from .shared import results_per_domain, aggregate_subreports
from .shared import resolve_a_aaaa, batch_resolve_a_aaaa
from .shared import mail_get_servers, batch_mail_get_servers
from .tls_connection import MAX_REDIRECT_DEPTH, NoIpError
from .tls_connection import DebugConnection, ModernConnection
from .tls_connection import ConnectionHandshakeException
from .tls_connection import ConnectionSocketException
from .tls_connection import SSLConnectionWrapper
from .tls_connection import SSLV23, SSLV2, SSLV3, TLSV1, TLSV1_1, TLSV1_2
from .tls_connection import HTTPSConnection, CipherListAction, TLSV1_3
from .tls_connection import http_fetch
from .cipher_info import cipher_infos, SecLevel, CipherScoreAndSecLevel
from .. import scoring, categories
from .. import batch, batch_shared_task, redis_id
from ..models import DaneStatus, DomainTestTls, MailTestTls, WebTestTls
from ..models import ForcedHttpsStatus, OcspStatus, ZeroRttStatus
from ..models import KexHashFuncStatus, CipherOrderStatus, MxStatus


# Workaround for https://github.com/eventlet/eventlet/issues/413 for eventlet
# while monkey patching. That way we can still catch subprocess.TimeoutExpired
# instead of just Exception which may intervene with Celery's own exceptions.
# Gevent does not have the same issue.
import eventlet
if eventlet.patcher.is_monkey_patched('subprocess'):
    subprocess = eventlet.import_patched('subprocess')
else:
    import subprocess

try:
    from ssl import OP_NO_SSLv2, OP_NO_SSLv3
except ImportError as e:
    # Support for older python versions, not for use in production
    if settings.DEBUG:
        OP_NO_SSLv2 = 16777216
        OP_NO_SSLv3 = 33554432
    else:
        raise e

logger = logging.getLogger('internetnl')

# Based on:
# hhttps://tools.ietf.org/html/rfc5246#section-7.4.1.4.1 "Signature Algorithms"
# https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set1_sigalgs_list.html
# https://www.openssl.org/docs/man1.1.0/man3/SSL_CONF_cmd.html
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-16
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-18
# openssl list -1 -digest-commands
# Define signature algorithms which, if we are unable to connect using any of
# them, constitutes a phase out warning. See NCSC 2.0 "Table 5 - Hash functions
# for key exchange".
# Only SHA256/384/512 based hash functions:
KEX_TLS12_SHA2_HASHALG_PREFERRED_ORDER = [
    'SHA512',
    'SHA384',
    'SHA256',
]
# All possible algorithms:
KEX_TLS12_SIGALG_PREFERRED_ORDER = [
    'RSA',
    'RSA-PSS',
    'DSA',
    'ECDSA',
]
KEX_TLS12_SORTED_ALG_COMBINATIONS = map('+'.join, product(
    KEX_TLS12_SIGALG_PREFERRED_ORDER, KEX_TLS12_SHA2_HASHALG_PREFERRED_ORDER))
KEX_TLS12_SHA2_SIGALG_PREFERENCE = ':'.join(KEX_TLS12_SORTED_ALG_COMBINATIONS)

# Based on:
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-signaturescheme
# https://www.openssl.org/docs/man1.1.0/man3/SSL_CONF_cmd.html
# https://tools.ietf.org/html/rfc8446#section-4.2.3
# https://tools.ietf.org/html/rfc8032 "EdDSA"
# NCSC 2.0 Table 5 - Hash functions for key exchange
# Only signature schemes that are SHA256/384/512 based:
#   ed25519 is included in the table because RFC-8032 states that it is SHA-512
#   based.
#   ed448 is excluded from the table because RFC-8032 states that it is SHAKE256
#   (SHA-3) based.
KEX_TLS13_SHA2_SIGNATURE_SCHEMES = [
    'rsa_pkcs1_sha512',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha256',
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha512',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha256',
    'ed25519',
    'rsa_pss_pss_sha512',
    'rsa_pss_pss_sha384',
    'rsa_pss_pss_sha256',
]
KEX_TLS13_SHA2_SIGALG_PREFERENCE = ':'.join(KEX_TLS13_SHA2_SIGNATURE_SCHEMES)

KEX_GOOD_HASH_FUNCS = frozenset(
    set(KEX_TLS12_SHA2_HASHALG_PREFERRED_ORDER) |
    set(KEX_TLS13_SHA2_SIGNATURE_SCHEMES))

# Need to be lists because we want them in specific order for testing when
# combining with other security levels i.e., more secure > less secure. The
# cipher order test relies on that order.

# These ciphers are only available on SSL2 that we need to explicitly set.
INSUFFICIENT_CIPHERS_SSLV2 = {x.name for x in filter(
    lambda x: (DebugConnection in x.supported_conns and
               x.sec_level == SecLevel.INSUFFICIENT and
               x.tls_version == 'SSLv2'),
    cipher_infos.values())}
INSUFFICIENT_CIPHERS = {x.name for x in filter(
    lambda x: (DebugConnection in x.supported_conns and
               x.sec_level == SecLevel.INSUFFICIENT),
    cipher_infos.values())} - INSUFFICIENT_CIPHERS_SSLV2
INSUFFICIENT_CIPHERS_MODERN = list({x.name for x in filter(
    lambda x: (ModernConnection in x.supported_conns and
               x.sec_level == SecLevel.INSUFFICIENT),
    cipher_infos.values())} - INSUFFICIENT_CIPHERS)
INSUFFICIENT_CIPHERS = list(INSUFFICIENT_CIPHERS)
INSUFFICIENT_CIPHERS_SSLV2 = list(INSUFFICIENT_CIPHERS_SSLV2)

PHASE_OUT_CIPHERS = {x.name for x in filter(
    lambda x: (DebugConnection in x.supported_conns and
               x.sec_level == SecLevel.PHASE_OUT),
    cipher_infos.values())}
PHASE_OUT_CIPHERS_MODERN = list({x.name for x in filter(
    lambda x: (ModernConnection in x.supported_conns and
               x.sec_level == SecLevel.PHASE_OUT),
    cipher_infos.values())} - PHASE_OUT_CIPHERS)
PHASE_OUT_CIPHERS = list(PHASE_OUT_CIPHERS)

SUFFICIENT_DEBUG_CIPHERS = {x.name for x in filter(
    lambda x: (DebugConnection in x.supported_conns and
               x.sec_level == SecLevel.SUFFICIENT),
    cipher_infos.values())}
SUFFICIENT_MODERN_CIPHERS = {x.name for x in filter(
    lambda x: (ModernConnection in x.supported_conns and
               x.sec_level == SecLevel.SUFFICIENT),
    cipher_infos.values())}

GOOD_SUFFICIENT_SEC_LEVELS = frozenset([SecLevel.GOOD, SecLevel.SUFFICIENT])
GOOD_SUFFICIENT_DEBUG_CIPHERS = {x.name for x in filter(
    lambda x: (DebugConnection in x.supported_conns and
               x.sec_level in GOOD_SUFFICIENT_SEC_LEVELS),
    cipher_infos.values())}
GOOD_SUFFICIENT_MODERN_CIPHERS = {x.name for x in filter(
    lambda x: (ModernConnection in x.supported_conns and
               x.sec_level in GOOD_SUFFICIENT_SEC_LEVELS),
    cipher_infos.values())}


# Based on: https://tools.ietf.org/html/rfc7919#appendix-A
FFDHE2048_PRIME = int(
    (
        "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
        "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
        "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
        "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
        "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
        "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
        "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
        "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
        "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
        "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
        "886B4238 61285C97 FFFFFFFF FFFFFFFF"
    ).replace(' ', ''), 16)
FFDHE3072_PRIME = int(
    (
        "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
        "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
        "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
        "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
        "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
        "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
        "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
        "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
        "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
        "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
        "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
        "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
        "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
        "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
        "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
        "3C1B20EE 3FD59D7C 25E41D2B 66C62E37 FFFFFFFF FFFFFFFF"
    ).replace(' ', ''), 16)
FFDHE4096_PRIME = int(
    (
        "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
        "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
        "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
        "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
        "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
        "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
        "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
        "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
        "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
        "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
        "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
        "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
        "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
        "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
        "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
        "3C1B20EE 3FD59D7C 25E41D2B 669E1EF1 6E6F52C3 164DF4FB"
        "7930E9E4 E58857B6 AC7D5F42 D69F6D18 7763CF1D 55034004"
        "87F55BA5 7E31CC7A 7135C886 EFB4318A ED6A1E01 2D9E6832"
        "A907600A 918130C4 6DC778F9 71AD0038 092999A3 33CB8B7A"
        "1A1DB93D 7140003C 2A4ECEA9 F98D0ACC 0A8291CD CEC97DCF"
        "8EC9B55A 7F88A46B 4DB5A851 F44182E1 C68A007E 5E655F6A"
        "FFFFFFFF FFFFFFFF"
    ).replace(' ', ''), 16)
FFDHE6144_PRIME = int(
    (
        "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
        "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
        "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
        "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
        "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
        "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
        "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
        "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
        "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
        "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
        "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
        "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
        "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
        "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
        "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
        "3C1B20EE 3FD59D7C 25E41D2B 669E1EF1 6E6F52C3 164DF4FB"
        "7930E9E4 E58857B6 AC7D5F42 D69F6D18 7763CF1D 55034004"
        "87F55BA5 7E31CC7A 7135C886 EFB4318A ED6A1E01 2D9E6832"
        "A907600A 918130C4 6DC778F9 71AD0038 092999A3 33CB8B7A"
        "1A1DB93D 7140003C 2A4ECEA9 F98D0ACC 0A8291CD CEC97DCF"
        "8EC9B55A 7F88A46B 4DB5A851 F44182E1 C68A007E 5E0DD902"
        "0BFD64B6 45036C7A 4E677D2C 38532A3A 23BA4442 CAF53EA6"
        "3BB45432 9B7624C8 917BDD64 B1C0FD4C B38E8C33 4C701C3A"
        "CDAD0657 FCCFEC71 9B1F5C3E 4E46041F 388147FB 4CFDB477"
        "A52471F7 A9A96910 B855322E DB6340D8 A00EF092 350511E3"
        "0ABEC1FF F9E3A26E 7FB29F8C 183023C3 587E38DA 0077D9B4"
        "763E4E4B 94B2BBC1 94C6651E 77CAF992 EEAAC023 2A281BF6"
        "B3A739C1 22611682 0AE8DB58 47A67CBE F9C9091B 462D538C"
        "D72B0374 6AE77F5E 62292C31 1562A846 505DC82D B854338A"
        "E49F5235 C95B9117 8CCF2DD5 CACEF403 EC9D1810 C6272B04"
        "5B3B71F9 DC6B80D6 3FDD4A8E 9ADB1E69 62A69526 D43161C1"
        "A41D570D 7938DAD4 A40E329C D0E40E65 FFFFFFFF FFFFFFFF"
    ).replace(' ', ''), 16)
FFDHE8192_PRIME = int(
    (
        "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
        "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
        "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
        "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
        "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
        "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
        "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
        "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
        "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
        "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
        "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
        "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
        "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
        "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
        "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
        "3C1B20EE 3FD59D7C 25E41D2B 669E1EF1 6E6F52C3 164DF4FB"
        "7930E9E4 E58857B6 AC7D5F42 D69F6D18 7763CF1D 55034004"
        "87F55BA5 7E31CC7A 7135C886 EFB4318A ED6A1E01 2D9E6832"
        "A907600A 918130C4 6DC778F9 71AD0038 092999A3 33CB8B7A"
        "1A1DB93D 7140003C 2A4ECEA9 F98D0ACC 0A8291CD CEC97DCF"
        "8EC9B55A 7F88A46B 4DB5A851 F44182E1 C68A007E 5E0DD902"
        "0BFD64B6 45036C7A 4E677D2C 38532A3A 23BA4442 CAF53EA6"
        "3BB45432 9B7624C8 917BDD64 B1C0FD4C B38E8C33 4C701C3A"
        "CDAD0657 FCCFEC71 9B1F5C3E 4E46041F 388147FB 4CFDB477"
        "A52471F7 A9A96910 B855322E DB6340D8 A00EF092 350511E3"
        "0ABEC1FF F9E3A26E 7FB29F8C 183023C3 587E38DA 0077D9B4"
        "763E4E4B 94B2BBC1 94C6651E 77CAF992 EEAAC023 2A281BF6"
        "B3A739C1 22611682 0AE8DB58 47A67CBE F9C9091B 462D538C"
        "D72B0374 6AE77F5E 62292C31 1562A846 505DC82D B854338A"
        "E49F5235 C95B9117 8CCF2DD5 CACEF403 EC9D1810 C6272B04"
        "5B3B71F9 DC6B80D6 3FDD4A8E 9ADB1E69 62A69526 D43161C1"
        "A41D570D 7938DAD4 A40E329C CFF46AAA 36AD004C F600C838"
        "1E425A31 D951AE64 FDB23FCE C9509D43 687FEB69 EDD1CC5E"
        "0B8CC3BD F64B10EF 86B63142 A3AB8829 555B2F74 7C932665"
        "CB2C0F1C C01BD702 29388839 D2AF05E4 54504AC7 8B758282"
        "2846C0BA 35C35F5C 59160CC0 46FD8251 541FC68C 9C86B022"
        "BB709987 6A460E74 51A8A931 09703FEE 1C217E6C 3826E52C"
        "51AA691E 0E423CFC 99E9E316 50C1217B 624816CD AD9A95F9"
        "D5B80194 88D9C0A0 A1FE3075 A577E231 83F81D4A 3F2FA457"
        "1EFC8CE0 BA8A4FE8 B6855DFE 72B0A66E DED2FBAB FBE58A30"
        "FAFABE1C 5D71A87E 2F741EF8 C1FE86FE A6BBFDE5 30677F0D"
        "97D11D49 F7A8443D 0822E506 A9F4614E 011E2A94 838FF88C"
        "D68C8BB7 C5C6424C FFFFFFFF FFFFFFFF"
    ).replace(' ', ''), 16)
FFDHE_GENERATOR = 2
FFDHE_SUFFICIENT_PRIMES = [
    FFDHE8192_PRIME, FFDHE6144_PRIME, FFDHE4096_PRIME, FFDHE3072_PRIME]


# Maximum number of tries on failure to establish a connection.
# Useful on one-time errors on SMTP.
MAX_TRIES = 3


root_fingerprints = None
with open(settings.CA_FINGERPRINTS) as f:
    root_fingerprints = f.read().splitlines()

test_map = {
    'web': {
        'model': WebTestTls,
        'category': categories.WebTls(),
        'testset_name': 'webtestset',
        'port': 443,
    },
    'mail': {
        'model': MailTestTls,
        'category': categories.MailTls(),
        'testset_name': 'testset',
        'port': 25,
    },
}


class ChecksMode(Enum):
    WEB = 0,
    MAIL = 1


@shared_task(bind=True)
def web_callback(self, results, domain, req_limit_id):
    """
    Save results in db.

    """
    webdomain, results = callback(results, domain, 'web')
    # Always calculate scores on saving.
    from ..probes import web_probe_tls
    web_probe_tls.rated_results_by_model(webdomain)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_web_callback(self, results, domain):
    webdomain, results = callback(results, domain, 'web')
    # Always calculate scores on saving.
    from ..probes import batch_web_probe_tls
    batch_web_probe_tls.rated_results_by_model(webdomain)
    batch.scheduler.batch_callback_hook(webdomain, self.request.id)


@shared_task(bind=True)
def mail_callback(self, results, domain, req_limit_id):
    maildomain, results = callback(results, domain, 'mail')
    # Always calculate scores on saving.
    from ..probes import mail_probe_tls
    mail_probe_tls.rated_results_by_model(maildomain)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_mail_callback(self, results, domain):
    maildomain, results = callback(results, domain, 'mail')
    # Always calculate scores on saving.
    from ..probes import batch_mail_probe_tls
    batch_mail_probe_tls.rated_results_by_model(maildomain)
    batch.scheduler.batch_callback_hook(maildomain, self.request.id)


@transaction.atomic
def callback(results, domain, test_type):
    results = results_per_domain(results)
    if 'mx_status' in results:
        return callback_null_mx(results, domain, test_type)
    testdomain = test_map[test_type]['model'](domain=domain)
    if testdomain is MailTestTls:
        testdomain.mx_status = MxStatus.has_mx
    testdomain.save()
    category = test_map[test_type]['category']
    if len(results.keys()) > 0:
        for addr, res in results.items():
            category = category.__class__()
            dttls = DomainTestTls(domain=addr)
            dttls.port = test_map[test_type]['port']
            save_results(
                dttls, res, addr, domain, test_map[test_type]['category'])
            build_report(dttls, category)
            dttls.save()
            getattr(testdomain, test_map[test_type]['testset_name']).add(dttls)
    build_summary_report(testdomain, category)
    testdomain.save()
    return testdomain, results


def callback_null_mx(results, domain, test_type):
    testdomain = test_map[test_type]['model'](domain=domain)
    # Since we are here for the mail test and we have a variation of
    # the NULL MX record, we are pretty sure where to find the status.
    testdomain.mx_status = results['mx_status'][0][1]
    testdomain.save()
    category = test_map[test_type]['category']
    build_summary_report(testdomain, category)
    testdomain.save()
    return testdomain, results


web_registered = check_registry("web_tls", web_callback, resolve_a_aaaa)
batch_web_registered = check_registry(
    "batch_web_tls", batch_web_callback, batch_resolve_a_aaaa)
mail_registered = check_registry(
    "mail_tls", mail_callback, mail_get_servers)
batch_mail_registered = check_registry(
    "batch_mail_tls", batch_mail_callback, batch_mail_get_servers)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def web_cert(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_cert(af_ip_pairs, url, self, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_web_cert(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_cert(af_ip_pairs, url, self, *args, **kwargs)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def web_conn(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_conn(af_ip_pairs, url, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_web_conn(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_conn(af_ip_pairs, url, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def mail_smtp_starttls(self, mailservers, url, *args, **kwargs):
    return do_mail_smtp_starttls(mailservers, url, self, *args, **kwargs)


@batch_mail_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_mail_smtp_starttls(self, mailservers, url, *args, **kwargs):
    return do_mail_smtp_starttls(mailservers, url, self, *args, **kwargs)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def web_http(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_http(af_ip_pairs, url, self, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_web_http(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_http(af_ip_pairs, url, self, args, **kwargs)


def save_results(model, results, addr, domain, category):
    """
    Save results in DB.

    """
    if isinstance(category, categories.WebTls):
        for testname, result in results:
            if testname == "tls_conn":
                model.server_reachable = result.get("server_reachable", True)
                model.tls_enabled = result.get("tls_enabled")
                model.tls_enabled_score = result.get("tls_enabled_score", 0)
                if model.server_reachable and model.tls_enabled:
                    model.dh_param = result.get("dh_param")
                    model.ecdh_param = result.get("ecdh_param")
                    model.fs_bad = result.get("fs_bad")
                    model.fs_phase_out = result.get("fs_phase_out")
                    model.fs_score = result.get("fs_score")
                    model.ciphers_bad = result.get("ciphers_bad")
                    model.ciphers_phase_out = result.get("ciphers_phase_out")
                    model.ciphers_score = result.get("ciphers_score")
                    model.cipher_order = result.get("cipher_order")
                    model.cipher_order_score = result.get("cipher_order_score")
                    model.cipher_order_violation = result.get("cipher_order_violation")
                    model.protocols_good = result.get("prots_good")
                    model.protocols_sufficient = result.get("prots_sufficient")
                    model.protocols_bad = result.get("prots_bad")
                    model.protocols_phase_out = result.get("prots_phase_out")
                    model.protocols_score = result.get("prots_score")
                    model.compression = result.get("compression")
                    model.compression_score = result.get("compression_score")
                    model.secure_reneg = result.get("secure_reneg")
                    model.secure_reneg_score = result.get("secure_reneg_score")
                    model.client_reneg = result.get("client_reneg")
                    model.client_reneg_score = result.get("client_reneg_score")
                    model.zero_rtt = result.get("zero_rtt")
                    model.zero_rtt_score = result.get("zero_rtt_score")
                    model.ocsp_stapling = result.get("ocsp_stapling")
                    model.ocsp_stapling_score = result.get("ocsp_stapling_score")
                    model.kex_hash_func = result.get("kex_hash_func")
                    model.kex_hash_func_score = result.get("kex_hash_func_score")

            elif testname == "cert" and result.get("tls_cert"):
                model.cert_chain = result.get("chain")
                model.cert_trusted = result.get("trusted")
                model.cert_trusted_score = result.get("trusted_score")
                model.cert_pubkey_bad = result.get("pubkey_bad")
                model.cert_pubkey_phase_out = result.get("pubkey_phase_out")
                model.cert_pubkey_score = result.get("pubkey_score")
                model.cert_signature_bad = result.get("sigalg_bad")
                model.cert_signature_score = result.get("sigalg_score")
                model.cert_hostmatch_score = result.get("hostmatch_score")
                model.cert_hostmatch_bad = result.get("hostmatch_bad")
                model.dane_log = result.get("dane_log")
                model.dane_score = result.get("dane_score")
                model.dane_status = result.get("dane_status")
                model.dane_records = result.get("dane_records")
                model.dane_rollover = result.get("dane_rollover")

            elif testname == "http_checks":
                model.forced_https = result.get("forced_https")
                model.forced_https_score = result.get("forced_https_score")
                model.http_compression_enabled = result.get(
                    "http_compression_enabled")
                model.http_compression_score = result.get(
                    "http_compression_score")
                model.hsts_enabled = result.get("hsts_enabled")
                model.hsts_policies = result.get("hsts_policies")
                model.hsts_score = result.get("hsts_score")

    elif isinstance(category, categories.MailTls):
        for testname, result in results:
            if testname == "smtp_starttls":
                model.server_reachable = result.get("server_reachable", True)
                model.tls_enabled = result.get("tls_enabled")
                model.tls_enabled_score = result.get("tls_enabled_score", 0)
                model.could_not_test_smtp_starttls = result.get(
                    "could_not_test_smtp_starttls", False)
                if model.could_not_test_smtp_starttls:
                    # Special case where we couldn't connect for a test.
                    # Ignore all the subtests for this server.
                    continue

                if model.server_reachable and model.tls_enabled:
                    model.dh_param = result.get("dh_param")
                    model.ecdh_param = result.get("ecdh_param")
                    model.fs_bad = result.get("fs_bad")
                    model.fs_score = result.get("fs_score")
                    model.fs_phase_out = result.get("fs_phase_out")
                    model.ciphers_bad = result.get("ciphers_bad")
                    model.ciphers_phase_out = result.get("ciphers_phase_out")
                    model.ciphers_score = result.get("ciphers_score")
                    model.cipher_order = result.get("cipher_order")
                    model.cipher_order_score = result.get("cipher_order_score")
                    model.cipher_order_violation = result.get("cipher_order_violation")
                    model.protocols_bad = result.get("prots_bad")
                    model.protocols_phase_out = result.get("prots_phase_out")
                    model.protocols_score = result.get("prots_score")
                    model.compression = result.get("compression")
                    model.compression_score = result.get("compression_score")
                    model.secure_reneg = result.get("secure_reneg")
                    model.secure_reneg_score = result.get("secure_reneg_score")
                    model.client_reneg = result.get("client_reneg")
                    model.client_reneg_score = result.get("client_reneg_score")
                    model.zero_rtt = result.get("zero_rtt")
                    model.zero_rtt_score = result.get("zero_rtt_score")
                    # OCSP disabled for mail.
                    # model.ocsp_stapling = result.get("ocsp_stapling")
                    # model.ocsp_stapling_score = result.get("ocsp_stapling_score")
                    model.kex_hash_func = result.get("kex_hash_func")
                    model.kex_hash_func_score = result.get("kex_hash_func_score")
                if result.get("tls_cert"):
                    model.cert_chain = result.get("chain")
                    model.cert_trusted = result.get("trusted")
                    model.cert_trusted_score = result.get("trusted_score")
                    model.cert_pubkey_bad = result.get("pubkey_bad")
                    model.cert_pubkey_phase_out = result.get("pubkey_phase_out")
                    model.cert_pubkey_score = result.get("pubkey_score")
                    model.cert_signature_bad = result.get("sigalg_bad")
                    model.cert_signature_score = result.get("sigalg_score")
                    model.cert_hostmatch_score = result.get("hostmatch_score")
                    model.cert_hostmatch_bad = result.get("hostmatch_bad")
                    model.dane_log = result.get("dane_log")
                    model.dane_score = result.get("dane_score")
                    model.dane_status = result.get("dane_status")
                    model.dane_records = result.get("dane_records")
                    model.dane_rollover = result.get("dane_rollover")

    model.save()


def build_report(dttls, category):
    def annotate_and_combine(bad_items, phaseout_items):
        return [
            bad_items + phaseout_items,
            ['detail tech data insufficient'] * len(bad_items) +
            ['detail tech data phase-out'] * len(phaseout_items)]

    def annotate_and_combine_all(good_items, sufficient_items, bad_items, phaseout_items):
        return [
            good_items + sufficient_items + bad_items + phaseout_items,
            ['detail tech data secure'] * len(good_items) +
            ['detail tech data sufficient'] * len(sufficient_items) +
            ['detail tech data insufficient'] * len(bad_items) +
            ['detail tech data phase-out'] * len(phaseout_items)]



    if isinstance(category, categories.WebTls):
        if not dttls.server_reachable:
            category.subtests['https_exists'].result_unreachable()
        elif not dttls.tls_enabled:
            category.subtests['https_exists'].result_bad()
        else:
            category.subtests['https_exists'].result_good()

            if dttls.forced_https == ForcedHttpsStatus.good:
                category.subtests['https_forced'].result_good()
            elif dttls.forced_https == ForcedHttpsStatus.no_http:
                category.subtests['https_forced'].result_no_http()
            elif dttls.forced_https == ForcedHttpsStatus.bad:
                category.subtests['https_forced'].result_bad()

            if dttls.hsts_enabled:
                if dttls.hsts_score == scoring.WEB_TLS_HSTS_GOOD:
                    category.subtests['https_hsts'].result_good(
                        dttls.hsts_policies)
                else:
                    category.subtests['https_hsts'].result_bad_max_age(
                        dttls.hsts_policies)
            else:
                category.subtests['https_hsts'].result_bad()

            if dttls.http_compression_enabled:
                category.subtests['http_compression'].result_bad()
            else:
                category.subtests['http_compression'].result_good()

            if not dttls.dh_param and not dttls.ecdh_param:
                category.subtests['fs_params'].result_no_dh_params()
            else:
                fs_all = annotate_and_combine(dttls.fs_bad, dttls.fs_phase_out)
                if len(dttls.fs_bad) > 0:
                    category.subtests['fs_params'].result_bad(fs_all)
                elif len(dttls.fs_phase_out) > 0:
                    category.subtests['fs_params'].result_phase_out(fs_all)
                else:
                    category.subtests['fs_params'].result_good()

            ciphers_all = annotate_and_combine(
                dttls.ciphers_bad, dttls.ciphers_phase_out)
            if len(dttls.ciphers_bad) > 0:
                category.subtests['tls_ciphers'].result_bad(ciphers_all)
            elif len(dttls.ciphers_phase_out) > 0:
                category.subtests['tls_ciphers'].result_phase_out(ciphers_all)
            else:
                category.subtests['tls_ciphers'].result_good()

            if dttls.cipher_order == CipherOrderStatus.bad:
                category.subtests['tls_cipher_order'].result_bad()
            elif dttls.cipher_order == CipherOrderStatus.na:
                category.subtests['tls_cipher_order'].result_na()
            elif dttls.cipher_order == CipherOrderStatus.not_seclevel:
                (cipher1, cipher2, violated_rule) = dttls.cipher_order_violation
                category.subtests['tls_cipher_order'].result_seclevel_bad([
                        [cipher1, cipher2]
                    ])
            elif dttls.cipher_order == CipherOrderStatus.not_prescribed:
                # Provide tech_data that supplies values for two rows each of
                # two cells to fill in a table like so:
                # Web server IP address | Ciphers | Rule #
                # -------------------------------------------------------------
                # 1.2.3.4               | cipher1 | ' '
                # ...                   | cipher2 | violated_rule
                (cipher1, cipher2, violated_rule) = dttls.cipher_order_violation
                # The 5th rule is only informational.
                if violated_rule == 5:
                    category.subtests['tls_cipher_order'].result_score_info([
                            [cipher1, cipher2],
                            [' ', violated_rule]
                        ])
                else:
                    category.subtests['tls_cipher_order'].result_score_warning([
                            [cipher1, cipher2],
                            [' ', violated_rule]
                        ])
            else:
                category.subtests['tls_cipher_order'].result_good()

            protocols_all = annotate_and_combine_all(dttls.protocols_good,dttls.protocols_sufficient,
                dttls.protocols_bad, dttls.protocols_phase_out )

            if len(dttls.protocols_bad) > 0:
                category.subtests['tls_version'].result_bad(protocols_all)
            elif len(dttls.protocols_phase_out) > 0:
                category.subtests['tls_version'].result_phase_out(protocols_all)
            else:
                category.subtests['tls_version'].result_good(protocols_all)

            if dttls.compression:
                category.subtests['tls_compression'].result_bad()
            else:
                category.subtests['tls_compression'].result_good()

            if dttls.secure_reneg:
                category.subtests['renegotiation_secure'].result_good()
            else:
                category.subtests['renegotiation_secure'].result_bad()

            if dttls.client_reneg:
                category.subtests['renegotiation_client'].result_bad()
            else:
                category.subtests['renegotiation_client'].result_good()

            if not dttls.cert_chain:
                category.subtests['cert_trust'].result_could_not_test()
            else:
                if dttls.cert_trusted == 0:
                    category.subtests['cert_trust'].result_good()
                else:
                    category.subtests['cert_trust'].result_bad(dttls.cert_chain)

                if dttls.cert_pubkey_score is None:
                    pass
                else:
                    cert_pubkey_all = annotate_and_combine(
                        dttls.cert_pubkey_bad, dttls.cert_pubkey_phase_out)
                    if len(dttls.cert_pubkey_bad) > 0:
                        category.subtests['cert_pubkey'].result_bad(cert_pubkey_all)
                    elif len(dttls.cert_pubkey_phase_out) > 0:
                        category.subtests['cert_pubkey'].result_phase_out(cert_pubkey_all)
                    else:
                        category.subtests['cert_pubkey'].result_good()

                if dttls.cert_signature_score is None:
                    pass
                elif len(dttls.cert_signature_bad) > 0:
                    category.subtests['cert_signature'].result_bad(
                        dttls.cert_signature_bad)
                else:
                    category.subtests['cert_signature'].result_good()

                if dttls.cert_hostmatch_score is None:
                    pass
                elif len(dttls.cert_hostmatch_bad) > 0:
                    category.subtests['cert_hostmatch'].result_bad(
                        dttls.cert_hostmatch_bad)
                else:
                    category.subtests['cert_hostmatch'].result_good()

            if dttls.dane_status == DaneStatus.none:
                category.subtests['dane_exists'].result_bad()
            elif dttls.dane_status == DaneStatus.none_bogus:
                category.subtests['dane_exists'].result_bogus()
            else:
                category.subtests['dane_exists'].result_good(
                    dttls.dane_records)

                if dttls.dane_status == DaneStatus.validated:
                    category.subtests['dane_valid'].result_good()
                elif dttls.dane_status == DaneStatus.failed:
                    category.subtests['dane_valid'].result_bad()

                # Disabled for now.
                # if dttls.dane_rollover:
                #     category.subtests['dane_rollover'].result_good()
                # else:
                #     category.subtests['dane_rollover'].result_bad()

            if dttls.zero_rtt == ZeroRttStatus.good:
                category.subtests['zero_rtt'].result_good()
            elif dttls.zero_rtt == ZeroRttStatus.bad:
                category.subtests['zero_rtt'].result_bad()
            elif dttls.zero_rtt == ZeroRttStatus.na:
                category.subtests['zero_rtt'].result_na()

            if dttls.ocsp_stapling == OcspStatus.good:
                category.subtests['ocsp_stapling'].result_good()
            elif dttls.ocsp_stapling == OcspStatus.not_trusted:
                category.subtests['ocsp_stapling'].result_not_trusted()
            elif dttls.ocsp_stapling == OcspStatus.ok:
                category.subtests['ocsp_stapling'].result_ok()

            if dttls.kex_hash_func == KexHashFuncStatus.good:
                category.subtests['kex_hash_func'].result_good()
            elif dttls.kex_hash_func == KexHashFuncStatus.bad:
                category.subtests['kex_hash_func'].result_bad()
            elif dttls.kex_hash_func == KexHashFuncStatus.unknown:
                category.subtests['kex_hash_func'].result_unknown()

    elif isinstance(category, categories.MailTls):
        if dttls.could_not_test_smtp_starttls:
            category.subtests['starttls_exists'].result_could_not_test()
        elif not dttls.server_reachable:
            category.subtests['starttls_exists'].result_unreachable()
        elif not dttls.tls_enabled:
            category.subtests['starttls_exists'].result_bad()
        else:
            category.subtests['starttls_exists'].result_good()

            if not dttls.dh_param and not dttls.ecdh_param:
                category.subtests['fs_params'].result_no_dh_params()
            else:
                fs_all = annotate_and_combine(
                    dttls.fs_bad, dttls.fs_phase_out)
                if len(dttls.fs_bad) > 0:
                    category.subtests['fs_params'].result_bad(fs_all)
                elif len(dttls.fs_phase_out) > 0:
                    category.subtests['fs_params'].result_phase_out(fs_all)
                else:
                    category.subtests['fs_params'].result_good()

            ciphers_all = annotate_and_combine(
                dttls.ciphers_bad, dttls.ciphers_phase_out)
            if len(dttls.ciphers_bad) > 0:
                category.subtests['tls_ciphers'].result_bad(ciphers_all)
            elif len(dttls.ciphers_phase_out) > 0:
                category.subtests['tls_ciphers'].result_phase_out(ciphers_all)
            else:
                category.subtests['tls_ciphers'].result_good()

            if dttls.cipher_order == CipherOrderStatus.bad:
                category.subtests['tls_cipher_order'].result_bad()
            elif dttls.cipher_order == CipherOrderStatus.na:
                category.subtests['tls_cipher_order'].result_na()
            elif dttls.cipher_order == CipherOrderStatus.not_seclevel:
                (cipher1, cipher2, violated_rule) = dttls.cipher_order_violation
                category.subtests['tls_cipher_order'].result_seclevel_bad([
                        [cipher1, cipher2]
                    ])
            elif dttls.cipher_order == CipherOrderStatus.not_prescribed:
                # Provide tech_data that supplies values for two rows each of
                # two cells to fill in a table like so:
                # Web server IP address | Ciphers | Rule #
                # -------------------------------------------------------------
                # 1.2.3.4               | cipher1 | ' '
                # ...                   | cipher2 | violated_rule
                (cipher1, cipher2, violated_rule) = dttls.cipher_order_violation
                # The 5th rule is only informational.
                if violated_rule == 5:
                    category.subtests['tls_cipher_order'].result_score_info([
                            [cipher1, cipher2],
                            [' ', violated_rule]
                        ])
                else:
                    category.subtests['tls_cipher_order'].result_score_warning([
                            [cipher1, cipher2],
                            [' ', violated_rule]
                        ])
            else:
                category.subtests['tls_cipher_order'].result_good()

            protocols_all = annotate_and_combine(
                dttls.protocols_bad, dttls.protocols_phase_out)
            if len(dttls.protocols_bad) > 0:
                category.subtests['tls_version'].result_bad(protocols_all)
            elif len(dttls.protocols_phase_out) > 0:
                category.subtests['tls_version'].result_phase_out(protocols_all)
            else:
                category.subtests['tls_version'].result_good()

            if dttls.compression:
                category.subtests['tls_compression'].result_bad()
            else:
                category.subtests['tls_compression'].result_good()

            if dttls.secure_reneg:
                category.subtests['renegotiation_secure'].result_good()
            else:
                category.subtests['renegotiation_secure'].result_bad()

            if dttls.client_reneg:
                category.subtests['renegotiation_client'].result_bad()
            else:
                category.subtests['renegotiation_client'].result_good()

            if not dttls.cert_chain:
                category.subtests['cert_trust'].result_could_not_test()
            else:
                if dttls.cert_trusted == 0:
                    category.subtests['cert_trust'].result_good()
                else:
                    category.subtests['cert_trust'].result_bad(dttls.cert_chain)

                if dttls.cert_pubkey_score is None:
                    pass
                else:
                    cert_pubkey_all = annotate_and_combine(
                        dttls.cert_pubkey_bad, dttls.cert_pubkey_phase_out)
                    if len(dttls.cert_pubkey_bad) > 0:
                        category.subtests['cert_pubkey'].result_bad(cert_pubkey_all)
                    elif len(dttls.cert_pubkey_phase_out) > 0:
                        category.subtests['cert_pubkey'].result_phase_out(cert_pubkey_all)
                    else:
                        category.subtests['cert_pubkey'].result_good()

                if dttls.cert_signature_score is None:
                    pass
                elif len(dttls.cert_signature_bad) > 0:
                    category.subtests['cert_signature'].result_bad(
                        dttls.cert_signature_bad)
                else:
                    category.subtests['cert_signature'].result_good()

                if dttls.cert_hostmatch_score is None:
                    pass
                elif len(dttls.cert_hostmatch_bad) > 0:
                    # HACK: for DANE-TA(2) and hostname mismatch!
                    # Give a fail only if DANE-TA *is* present, otherwise info.
                    if has_daneTA(dttls.dane_records):
                        category.subtests['cert_hostmatch'].result_has_daneTA(
                            dttls.cert_hostmatch_bad)
                    else:
                        category.subtests['cert_hostmatch'].result_bad(
                            dttls.cert_hostmatch_bad)
                else:
                    category.subtests['cert_hostmatch'].result_good()

            if dttls.dane_status == DaneStatus.none:
                category.subtests['dane_exists'].result_bad()
            elif dttls.dane_status == DaneStatus.none_bogus:
                category.subtests['dane_exists'].result_bogus()
            else:
                category.subtests['dane_exists'].result_good(
                    dttls.dane_records)

                if dttls.dane_status == DaneStatus.validated:
                    category.subtests['dane_valid'].result_good()
                elif dttls.dane_status == DaneStatus.failed:
                    category.subtests['dane_valid'].result_bad()

                if dttls.dane_rollover:
                    category.subtests['dane_rollover'].result_good()
                else:
                    category.subtests['dane_rollover'].result_bad()

            if dttls.zero_rtt == ZeroRttStatus.good:
                category.subtests['zero_rtt'].result_good()
            elif dttls.zero_rtt == ZeroRttStatus.bad:
                category.subtests['zero_rtt'].result_bad()
            elif dttls.zero_rtt == ZeroRttStatus.na:
                category.subtests['zero_rtt'].result_na()

            # OCSP disabled for mail.
            # if dttls.ocsp_stapling == OcspStatus.good:
            #     category.subtests['ocsp_stapling'].result_good()
            # elif dttls.ocsp_stapling == OcspStatus.not_trusted:
            #     category.subtests['ocsp_stapling'].result_not_trusted()
            # elif dttls.ocsp_stapling == OcspStatus.ok:
            #     category.subtests['ocsp_stapling'].result_ok()

            if dttls.kex_hash_func == KexHashFuncStatus.good:
                category.subtests['kex_hash_func'].result_good()
            elif dttls.kex_hash_func == KexHashFuncStatus.bad:
                category.subtests['kex_hash_func'].result_bad()
            elif dttls.kex_hash_func == KexHashFuncStatus.unknown:
                category.subtests['kex_hash_func'].result_unknown()

    dttls.report = category.gen_report()


def build_summary_report(testtls, category):
    """
    Build the summary report for all the IP addresses.

    """
    category = category.__class__()
    if isinstance(category, categories.WebTls):
        category.subtests['https_exists'].result_bad()
        server_set = testtls.webtestset

    elif isinstance(category, categories.MailTls):
        if testtls.mx_status == MxStatus.null_mx:
            category.subtests['starttls_exists'].result_null_mx()
        elif testtls.mx_status == MxStatus.no_null_mx:
            category.subtests['starttls_exists'].result_no_null_mx()
        elif testtls.mx_status == MxStatus.invalid_null_mx:
            category.subtests['starttls_exists'].result_invalid_null_mx()
        else:
            category.subtests['starttls_exists'].result_no_mailservers()
        server_set = testtls.testset

    report = category.gen_report()
    subreports = {}
    for server_test in server_set.all():
        subreports[server_test.domain] = server_test.report

    aggregate_subreports(subreports, report)
    testtls.report = report


def dane(
        url, port, chain, task, dane_cb_data, score_none, score_none_bogus,
        score_failed, score_validated):
    """
    Check if there are TLSA records, if they are valid and if a DANE rollover
    scheme is currently in place.

    """
    score = score_none
    status = DaneStatus.none
    records = []
    stdout = ""
    rollover = False

    continue_testing = True

    cb_data = dane_cb_data or resolve_dane(task, port, url)

    # Check if there is a TLSA record, if TLSA records are bogus or NXDOMAIN is
    # returned for the TLSA domain (faulty signer).
    if not cb_data.get('data'):
        if cb_data.get('bogus'):
            status = DaneStatus.none_bogus
            score = score_none_bogus
        continue_testing = False
    else:
        if cb_data.get('secure'):
            # If there is a secure TLSA record check for the existence of
            # possible bogus (unsigned) NXDOMAIN in A.
            tmp_data = resolve_dane(task, port, url, check_nxdomain=True)
            if tmp_data.get('nxdomain') and tmp_data.get('bogus'):
                status = DaneStatus.none_bogus
                score = score_none_bogus
                continue_testing = False
        elif cb_data.get('bogus'):
            status = DaneStatus.failed
            score = score_failed
            continue_testing = False

    if not continue_testing:
        return dict(
            dane_score=score,
            dane_status=status,
            dane_log=stdout,
            dane_records=records,
            dane_rollover=rollover,
        )

    # Record TLSA data and also check for DANE rollover types.
    # Accepted pairs are:
    # * 3 x x - 3 x x
    # * 3 x x - 2 x x
    two_x_x = 0
    three_x_x = 0
    for cert_usage, selector, match, data in cb_data["data"]:
        if port == 25 and cert_usage in (0, 1):
            # Ignore PKIX TLSA records for mail.
            continue

        records.append("{} {} {} {}".format(cert_usage, selector, match, data))
        if cert_usage == 2:
            two_x_x += 1
        elif cert_usage == 3:
            three_x_x += 1

    if not records:
        return dict(
            dane_score=score,
            dane_status=status,
            dane_log=stdout,
            dane_records=records,
            dane_rollover=rollover,
        )

    if three_x_x > 1 or (three_x_x and two_x_x):
        rollover = True

    # Remove the trailing dot if any.
    hostname = url.rstrip(".")

    chain_pem = []
    for cert in chain:
        chain_pem.append(cert.as_pem())
    chain_txt = "\n".join(chain_pem)
    res = None
    with subprocess.Popen(
            [
                settings.LDNS_DANE,
                '-c', '/dev/stdin',  # Read certificate chain from stdin
                '-n',  # Do not validate hostname
                '-T',  # Exit status 2 for PKIX without (secure) TLSA records
                '-f', settings.CA_CERTIFICATES,  # CA file
                'verify', hostname, str(port),
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.PIPE, universal_newlines=True) as proc:

        try:
            res = proc.communicate(input=chain_txt, timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            res = proc.communicate()

    # status 0: DANE validate
    # status 1: ERROR
    # status 2: PKIX ok, no TLSA
    if res:
        stdout, stderr = res

        if ("No usable TLSA records" in stdout
                or "No usable TLSA records" in stderr):
            score = score_failed
            status = DaneStatus.failed
        elif ("No TLSA records" not in stdout
                and "No TLSA records" not in stderr):
            if proc.returncode == 0:
                score = score_validated
                status = DaneStatus.validated
            elif proc.returncode == 1:
                score = score_failed
                status = DaneStatus.failed

        # Log stderr if stdout is empty.
        if not stdout:
            stdout = stderr

    return dict(
        dane_score=score,
        dane_status=status,
        dane_log=stdout,
        dane_records=records,
        dane_rollover=rollover,
    )


def is_root_cert(cert):
    """
    Check if the certificate is a root certificate.

    """
    digest = cert.fingerprint(hashes.SHA1())
    digest = hexlify(digest).decode('ascii')
    return digest.upper() in root_fingerprints


def get_common_name(cert):
    """
    Get the commonName of the certificate.

    """
    value = "-"
    try:
        common_name = (
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0])
        if common_name:
            value = common_name.value
    except (IndexError, ValueError):
        pass
    return value


class DebugCertChain(object):
    """
    Class performing X509 cert checks NCSC Guidelines B3-*

    """
    def __new__(cls, chain):
        """
        In case the chain is None (ValueError from nassl) don't create an
        instance. Instead return None and it will be handled during the
        certificate checks.

        """
        if chain is None:
            return None
        return super(DebugCertChain, cls).__new__(cls)

    def __init__(self, chain):
        self.unparsed_chain = chain
        self.chain = [
            load_pem_x509_certificate(
                cert.as_pem().encode("ascii"), backend=default_backend())
            for cert in chain
        ]
        self.score_hostmatch_good = scoring.WEB_TLS_HOSTMATCH_GOOD
        self.score_hostmatch_bad = scoring.WEB_TLS_HOSTMATCH_BAD
        self.score_pubkey_good = scoring.WEB_TLS_PUBKEY_GOOD
        self.score_pubkey_bad = scoring.WEB_TLS_PUBKEY_BAD
        self.score_signature_good = scoring.WEB_TLS_SIGNATURE_GOOD
        self.score_signature_bad = scoring.WEB_TLS_SIGNATURE_BAD
        self.score_dane_none = scoring.WEB_TLS_DANE_NONE
        self.score_dane_none_bogus = scoring.WEB_TLS_DANE_NONE_BOGUS
        self.score_dane_failed = scoring.WEB_TLS_DANE_FAILED
        self.score_dane_validated = scoring.WEB_TLS_DANE_VALIDATED

    def check_hostname(self, url):
        """
        Check the hostname on the leaf certificate (commonName and SANs).

        """
        bad_hostmatch = []
        common_name = get_common_name(self.chain[0])
        try:
            sans = self.chain[0].extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = sans.value.get_values_for_type(DNSName)
        except ExtensionNotFound:
            sans = []

        ssl_cert_parts = {
            'subject': (tuple([('commonName', common_name)]),),
            'subjectAltName': tuple([('DNS', name) for name in sans]),
        }
        try:
            ssl.match_hostname(ssl_cert_parts, url.rstrip("."))
            hostmatch_score = self.score_hostmatch_good
        except ssl.CertificateError:
            hostmatch_score = self.score_hostmatch_bad
            # bad_hostmatch was of the form list(CN, list(SAN, SAN, ..)). In
            # the report the CN is shown on one row of the tech table and the
            # SANs are shown as '[SAN, SAN]' on a second row. Showing the SANs
            # in the report as the string representation of a Python list is a
            # separate issue so ignore that for the moment. It is possible for
            # there to be duplicates and overlap between the SANs and the CN
            # which when shown in a report column titled 'Unmatched domains on
            # certificate' looks odd to have duplicate entries. I have
            # flattened this to the form list(CN, SAN, SAN, ..) while still
            # preserving the order. As Python doesn't have an OrderedSet type
            # and adding one is overkill I use a trick to remove duplicates in
            # the ordered list. See:
            # https://www.w3schools.com/python/python_howto_remove_duplicates.asp
            # However, was anyone relying on the nested structure of this
            # result value, e.g. perhaps via the Internet.NL batch API?
            bad_hostmatch.append(common_name)
            bad_hostmatch.extend(sans)
            bad_hostmatch = list(dict.fromkeys(bad_hostmatch))  # de-dupe
        return hostmatch_score, bad_hostmatch

    # NCSC guidelines B3-3, B5-1
    def check_pubkey(self):
        bad_pubkey = []
        phase_out_pubkey = []
        pubkey_score = self.score_pubkey_good
        for cert in self.chain:
            common_name = get_common_name(cert)
            public_key = cert.public_key()
            public_key_type = type(public_key)
            bits = public_key.key_size

            failed_key_type = ""
            curve = ""
            if public_key_type is _RSAPublicKey and bits < 2048:
                failed_key_type = "RSAPublicKey"
            elif public_key_type is _DSAPublicKey and bits < 2048:
                failed_key_type = "DSAPublicKey"
            elif public_key_type is _DHPublicKey and bits < 2048:
                failed_key_type = "DHPublicKey"
            elif public_key_type is _EllipticCurvePublicKey:
                curve = public_key.curve.name
                if (curve not in [
                        "secp384r1",
                        "secp256r1",
                        "x448",
                        "x25519",
                        ] or bits < 224):
                    failed_key_type = "EllipticCurvePublicKey"
            if failed_key_type:
                message = "{}: {}-{} bits".format(
                    common_name, failed_key_type, bits)
                if curve:
                    message += ", curve: {}".format(curve)
                if curve == "secp224r1":
                    phase_out_pubkey.append(message)
                else:
                    bad_pubkey.append(message)
                    pubkey_score = self.score_pubkey_bad
        return pubkey_score, bad_pubkey, phase_out_pubkey

    def check_sigalg(self):
        """
        Check whether the certificate is signed using a good algorithm.

        Good algorithms are: sha512, sha384, sha256
        NCSC guideline B3-2

        """
        bad_sigalg = {}
        sigalg_score = self.score_signature_good
        for cert in self.chain:
            # Only validate signarture of non-root certificates
            if not is_root_cert(cert):
                sigalg = cert.signature_algorithm_oid
                # Check oids
                if sigalg not in (
                        SignatureAlgorithmOID.RSA_WITH_SHA256,
                        SignatureAlgorithmOID.RSA_WITH_SHA384,
                        SignatureAlgorithmOID.RSA_WITH_SHA512,
                        SignatureAlgorithmOID.ECDSA_WITH_SHA256,
                        SignatureAlgorithmOID.ECDSA_WITH_SHA384,
                        SignatureAlgorithmOID.ECDSA_WITH_SHA512,
                        SignatureAlgorithmOID.DSA_WITH_SHA256):
                    bad_sigalg[get_common_name(cert)] = sigalg._name
                    sigalg_score = self.score_signature_bad
        return sigalg_score, bad_sigalg

    def chain_str(self):
        """
        Return a list containing the commonNames of the certificate chain.

        """
        chain_str = []
        for cert in self.chain:
            chain_str.append(get_common_name(cert))

        return chain_str

    def check_dane(self, url, port, task, dane_cb_data=None):
        return dane(
            url, port, self.unparsed_chain, task, dane_cb_data,
            self.score_dane_none, self.score_dane_none_bogus,
            self.score_dane_failed, self.score_dane_validated)


class DebugCertChainMail(DebugCertChain):
    """
    Subclass of DebugCertChain to define the scores used for the mailtest.

    """
    def __init__(self, chain):
        super(DebugCertChainMail, self).__init__(chain)
        self.score_hostmatch_good = scoring.MAIL_TLS_HOSTMATCH_GOOD
        self.score_hostmatch_bad = scoring.MAIL_TLS_HOSTMATCH_BAD
        self.score_pubkey_good = scoring.MAIL_TLS_PUBKEY_GOOD
        self.score_pubkey_bad = scoring.MAIL_TLS_PUBKEY_BAD
        self.score_signature_good = scoring.MAIL_TLS_SIGNATURE_GOOD
        self.score_signature_bad = scoring.MAIL_TLS_SIGNATURE_BAD
        self.score_dane_none = scoring.MAIL_TLS_DANE_NONE
        self.score_dane_none_bogus = scoring.MAIL_TLS_DANE_NONE_BOGUS
        self.score_dane_failed = scoring.MAIL_TLS_DANE_FAILED
        self.score_dane_validated = scoring.MAIL_TLS_DANE_VALIDATED


class SMTPConnectionCouldNotTestException(Exception):
    """
    Used on the SMTP STARTTLS test.

    Used when we have time outs on establishing a connection or when a mail
    server replies with an error upon connecting.

    """
    pass


def starttls_sock_setup(conn):
    """
    Setup socket for SMTP STARTTLS.

    Retries to connect when we get an error code upon connecting.

    Raises SMTPConnectionCouldNotTestException when we get no reply
    from the server or when the server still replies with an error code
    upon connecting after a number of retries.

    """
    def readline(fd, maximum_bytes=4096):
        line = fd.readline(maximum_bytes).decode('ascii')
        return line

    conn.sock = None

    # If we get an error code(4xx, 5xx) in the first reply upon
    # connecting, we will retry in case it was a one time error.
    #
    # From: https://www.rfc-editor.org/rfc/rfc3207.html#section-5
    #    S: <waits for connection on TCP port 25>
    # 1  C: <opens connection>
    # 2  S: 220 mail.imc.org SMTP service ready
    # 3  C: EHLO mail.example.com
    # 4  S: 250-mail.imc.org offers a warm hug of welcome
    # 5  S: 250-8BITMIME
    #    S: 250-STARTTLS
    #    S: 250 DSN
    # 6  C: STARTTLS
    # 7  S: 220 Go ahead
    #    C: <starts TLS negotiation>
    #    C & S: <negotiate a TLS session>
    #    C & S: <check result of negotiation>
    #    C: EHLO mail.example.com
    #    S: 250-mail.imc.org touches your hand gently for a moment
    #    S: 250-8BITMIME
    #    S: 250 DSN
    tries_left = conn.tries
    retry = True
    while retry and tries_left > 0:
        retry = False
        try:
            # 1
            conn.sock_connect(any_af=True)

            # 2
            fd = conn.sock.makefile("rb")
            line = readline(fd)

            if (line and line[3] == " " and
                    (line[0] == '4' or line[0] == '5')):
                # The server replied with an error code.
                # We will retry to connect in case it was an one time
                # error.
                conn.safe_shutdown()
                tries_left -= 1
                retry = True
                if tries_left <= 0:
                    raise SMTPConnectionCouldNotTestException()
                time.sleep(1)
                continue

            while line and line[3] != " ":
                line = readline(fd)

            # 3
            conn.sock.sendall(bytes(
                f"EHLO {settings.SMTP_EHLO_DOMAIN}\r\n", 'ascii'))

            starttls = False

            # 4
            line = readline(fd)
            while line and line[3] != " ":
                if "STARTTLS" in line:
                    # 5
                    starttls = True
                line = readline(fd)

            if starttls or "STARTTLS" in line:
                # 6
                conn.sock.sendall(b"STARTTLS\r\n")
                # 7
                readline(fd)
                fd.close()
            else:
                fd.close()
                raise ConnectionHandshakeException()

        except (socket.error, socket.timeout, socket.gaierror):
            # We didn't get a reply back, this means our packets
            # are dropped. This happened in cases where a rate
            # limiting mechanism was in place. Skip the test.
            if conn.sock:
                conn.safe_shutdown()
            raise ConnectionSocketException()
        except IOError as e:
            # We can't reach the server.
            if conn.sock:
                conn.safe_shutdown()
            if e.errno in [
                    errno.ENETUNREACH, errno.EHOSTUNREACH,
                    errno.ECONNREFUSED, errno.ENOEXEC]:
                raise ConnectionSocketException()
            raise e
        except NoIpError:
            raise ConnectionSocketException()


class SMTPConnection(SSLConnectionWrapper):
    def __init__(self, *args, port=25, timeout=24, **kwargs):
        super().__init__(
            *args, timeout=timeout, port=port,
            sock_setup=starttls_sock_setup, **kwargs)


class StarttlsDetails:
    """
    Class used to store starttls details for the mail test.

    """
    def __init__(
            self, debug_chain=None, trusted_score=None, conn_port=None,
            dane_cb_data=None):
        self.debug_chain = debug_chain
        self.trusted_score = trusted_score
        self.conn_port = conn_port
        self.dane_cb_data = dane_cb_data


def do_web_cert(af_ip_pairs, url, task, *args, **kwargs):
    """
    Check the web server's certificate.

    """
    try:
        results = {}
        for af_ip_pair in af_ip_pairs:
            results[af_ip_pair[1]] = cert_checks(
                url, ChecksMode.WEB, task, af_ip_pair, *args, **kwargs)
    except SoftTimeLimitExceeded:
        for af_ip_pair in af_ip_pairs:
            if not results.get(af_ip_pair[1]):
                results[af_ip_pair[1]] = dict(tls_cert=False)

    return ('cert', results)


def cert_checks(
        url, mode, task, af_ip_pair=None, starttls_details=None,
        *args, **kwargs):
    """
    Perform certificate checks.

    """
    try:
        # Generic arguments for web and mail.
        conn_wrapper_args = {
            'host': url,
            'task': task,
            'ciphers': "!aNULL",
            'cipher_list_action': CipherListAction.PREPEND
        }
        if mode == ChecksMode.WEB:
            # First try to connect to HTTPS. We don't care for
            # certificates in port 443 if there is no HTTPS there.
            http_client, *unused = http_fetch(
                url, af=af_ip_pair[0], path="", port=443,
                ip_address=af_ip_pair[1], depth=MAX_REDIRECT_DEPTH,
                task=web_cert)
            debug_cert_chain = DebugCertChain
            conn_wrapper = HTTPSConnection
            conn_wrapper_args['socket_af'] = af_ip_pair[0]
            conn_wrapper_args['ip_address'] = af_ip_pair[1]
        elif mode == ChecksMode.MAIL:
            debug_cert_chain = DebugCertChainMail
            conn_wrapper = SMTPConnection
            conn_wrapper_args['server_name'] = url
            conn_wrapper_args['send_SNI'] = (
                starttls_details.dane_cb_data.get('data')
                and starttls_details.dane_cb_data.get('secure'))
        else:
            raise ValueError

        if (not starttls_details or starttls_details.debug_chain is None
                or starttls_details.trusted_score is None
                or starttls_details.conn_port is None):
            # All the checks inside the smtp_starttls test are done in series.
            # If we have all the certificate related information we need from a
            # previous check, skip this connection.
            # check chain validity (sort of NCSC guideline B3-4)

            with conn_wrapper(**conn_wrapper_args).conn as conn:
                with ConnectionChecker(conn, mode) as checker:
                    verify_score, verify_result = checker.check_cert_trust()
                    debug_chain = debug_cert_chain(conn.get_peer_certificate_chain())
                    conn_port = conn.port
        else:
            verify_score, verify_result = starttls_details.trusted_score
            debug_chain = starttls_details.debug_chain
            conn_port = starttls_details.conn_port
    except (socket.error, http.client.BadStatusLine, NoIpError,
            ConnectionHandshakeException, ConnectionSocketException):
        return dict(tls_cert=False)

    if debug_chain is None:
        return dict(tls_cert=False)

    else:
        hostmatch_score, hostmatch_bad = debug_chain.check_hostname(url)
        pubkey_score, pubkey_bad, pubkey_phase_out = debug_chain.check_pubkey()
        sigalg_score, sigalg_bad = debug_chain.check_sigalg()
        chain_str = debug_chain.chain_str()

        if starttls_details:
            dane_results = debug_chain.check_dane(
                url, conn_port, task,
                dane_cb_data=starttls_details.dane_cb_data)
        else:
            dane_results = debug_chain.check_dane(
                url, conn_port, task)

        results = dict(
            tls_cert=True,
            chain=chain_str,
            trusted=verify_result,
            trusted_score=verify_score,
            pubkey_bad=pubkey_bad,
            pubkey_phase_out=pubkey_phase_out,
            pubkey_score=pubkey_score,
            sigalg_bad=sigalg_bad,
            sigalg_score=sigalg_score,
            hostmatch_bad=hostmatch_bad,
            hostmatch_score=hostmatch_score,
        )
        results.update(dane_results)

        return results


def do_web_conn(af_ip_pairs, url, *args, **kwargs):
    """
    Start all the TLS related checks for the web test.

    """
    try:
        results = {}
        for af_ip_pair in af_ip_pairs:
            results[af_ip_pair[1]] = check_web_tls(
                url, af_ip_pair, args, kwargs)
    except SoftTimeLimitExceeded:
        for af_ip_pair in af_ip_pairs:
            if not results.get(af_ip_pair[1]):
                results[af_ip_pair[1]] = dict(
                    server_reachable=False, tls_enabled=False)

    return ('tls_conn', results)


def do_mail_smtp_starttls(mailservers, url, task, *args, **kwargs):
    """
    Start all the TLS related checks for the mail test.

    If we already have cached results for these mailservers from another mail
    test use those to avoid contacting well known mailservers all the time.

    """
    # Check for NULL MX and return immediately.
    mx_status = get_mail_servers_mxstatus(mailservers)
    if mx_status != MxStatus.has_mx:
        return ('smtp_starttls', {'mx_status': mx_status})

    results = {server: False for server, _, _ in mailservers}
    try:
        start = timer()
        # Sleep in order for the ipv6 mail test to finish.
        # Cheap counteraction for some mailservers that allow only one
        # concurrent connection per IP.
        time.sleep(5)

        # Always try to get cached results (within the allowed time frame) to
        # avoid continuously testing popular mail hosting providers.
        cache_ttl = redis_id.mail_starttls.ttl
        while timer() - start < cache_ttl and not all(results.values()) > 0:
            for server, dane_cb_data, _ in mailservers:
                if results[server]:
                    continue
                # Check if we already have cached results.
                cache_id = redis_id.mail_starttls.id.format(server)
                if cache.add(cache_id, False, cache_ttl):
                    # We do not have cached results, get them and cache them.
                    results[server] = check_mail_tls(
                        server, dane_cb_data, task)
                    cache.set(cache_id, results[server], cache_ttl)
                else:
                    results[server] = cache.get(cache_id, False)
            time.sleep(1)
        for server in results:
            if results[server] is False:
                results[server] = dict(
                    tls_enabled=False, could_not_test_smtp_starttls=True)

    except SoftTimeLimitExceeded:
        for server in results:
            if results[server] is False:
                results[server] = dict(
                    tls_enabled=False, could_not_test_smtp_starttls=True)
    return ('smtp_starttls', results)


# At the time of writing this function makes up to 16 SMTP+STARTTLS connections
# to the target server, excluding retries, e.g.:
#   #   Connection Class    Protocol   Caller
#   ---------------------------------------------------------------------------
#   1   ModernConnection    SSLV23     initial connection
#   2   DebugConnection     SSLV23     initial connection (fallback 1)
#   3   ModernConnection    TLSV1_2    initial connection (fallback 2)
#   4   DebugConnection     SSLV23     check_client_reneg
#   5   DebugConnection     SSLV23     check_cipher_sec_level
#   6   DebugConnection     SSLV23     check_cipher_sec_level
#   7   ModernConnection    SSLV23     check_cipher_sec_level
#   8   ModernConnection    TLSV1_3    check_zero_rtt (if TLSV1_3)
#   9   DebugConnection     TLSV1_1    check_protocol_versions (if not initial)
#   10  DebugConnection     TLSV1      check_protocol_versions (if not initial)
#   11  DebugConnection     SSLV3      check_protocol_versions (if not initial)
#   12  DebugConnection     SSLV2      check_protocol_versions (if not initial)
#   13  DebugConnection     SSLV23     check_dh_params
#   14  DebugConnection     SSLV23     check_dh_params
#   15  ModernConnection    TLSV1_2    check_kex_hash_func (if not TLSV1_3)
#   16  DebugConnection     SSLV23     check_cipher_order
#   ---------------------------------------------------------------------------
def check_mail_tls(server, dane_cb_data, task):
    """
    Perform all the TLS related checks for this mail server in series.

    """
    try:
        starttls_details = StarttlsDetails()
        starttls_details.dane_cb_data = dane_cb_data
        send_SNI = (
            dane_cb_data.get('data')
            and dane_cb_data.get('secure'))

        with SMTPConnection(server_name=server, send_SNI=send_SNI).conn as conn:
            with ConnectionChecker(conn, ChecksMode.MAIL) as checker:
                # Record the starttls_details with the current connection.
                # It will skip a further connection for the cert_checks
                # later on.
                starttls_details.trusted_score = checker.check_cert_trust()
                starttls_details.debug_chain = DebugCertChainMail(
                    conn.get_peer_certificate_chain())
                starttls_details.conn_port = conn.port

                # OCSP disabled for mail.
                # ocsp_stapling_score, ocsp_stapling = checker.check_ocsp_stapling()

                # check_zero_rtt closes and reopens the main connection.
                # Close the main connection after testing, not needed anymore.
                # Tests below open their own connections.
                zero_rtt_score, zero_rtt = checker.check_zero_rtt()
                checker._conn.safe_shutdown()

                # check_compression and check_secure_reneg use a debug_conn.
                # Close it after testing.
                compression_score, compression = checker.check_compression()
                secure_reneg_score, secure_reneg = checker.check_secure_reneg()
                checker.close()

                # Checks here manage their own connections.
                client_reneg_score, client_reneg = checker.check_client_reneg()
                ciphers_score, ciphers_result = checker.check_cipher_sec_level()
                prots_score, prots_result = checker.check_protocol_versions()
                fs_score, fs_result = checker.check_dh_params()
                kex_hash_func_score, kex_hash_func = checker.check_kex_hash_func()
                cipher_order_score, cipher_order, cipher_order_violation = checker.check_cipher_order()

        # Check the certificates.
        cert_results = cert_checks(
            server, ChecksMode.MAIL, task,
            starttls_details=starttls_details)

        # HACK for DANE-TA(2) and hostname mismatch!
        # Give a good hosmatch score if DANE-TA *is not* present.
        if (cert_results['tls_cert']
                and not has_daneTA(cert_results['dane_records'])
                and cert_results['hostmatch_bad']):
            cert_results['hostmatch_score'] = scoring.MAIL_TLS_HOSTMATCH_GOOD

        results = dict(
            tls_enabled=True,
            tls_enabled_score=scoring.MAIL_TLS_STARTTLS_EXISTS_GOOD,
            prots_bad=prots_result['bad'],
            prots_phase_out=prots_result['phase_out'],
            prots_good=prots_result['good'],
            prots_sufficient=prots_result['sufficient'],
            prots_score=prots_score,

            ciphers_bad=ciphers_result['bad'],
            ciphers_phase_out=ciphers_result['phase_out'],
            ciphers_score=ciphers_score,
            cipher_order_score=cipher_order_score,
            cipher_order=cipher_order,
            cipher_order_violation=cipher_order_violation,

            secure_reneg=secure_reneg,
            secure_reneg_score=secure_reneg_score,
            client_reneg=client_reneg,
            client_reneg_score=client_reneg_score,
            compression=compression,
            compression_score=compression_score,

            dh_param=fs_result['dh_param'],
            ecdh_param=fs_result['ecdh_param'],
            fs_bad=fs_result['bad'],
            fs_phase_out=fs_result['phase_out'],
            fs_score=fs_score,

            zero_rtt_score=zero_rtt_score,
            zero_rtt=zero_rtt,

            # OCSP disabled for mail.
            # ocsp_stapling=ocsp_stapling,
            # ocsp_stapling_score=ocsp_stapling_score,

            kex_hash_func=kex_hash_func,
            kex_hash_func_score=kex_hash_func_score,
        )
        results.update(cert_results)

    except ConnectionSocketException:
        return dict(server_reachable=False)

    except ConnectionHandshakeException:
        return dict(tls_enabled=False)

    except SMTPConnectionCouldNotTestException:
        # If we could not test something, fail the starttls test.
        # We do not show partial results.
        return dict(
            tls_enabled=False,
            could_not_test_smtp_starttls=True,
        )

    return results


def has_daneTA(tlsa_records):
    """
    Check if any of the TLSA records is of type DANE-TA(2).

    """
    for tlsa in tlsa_records:
        if tlsa.startswith("2"):
            return True
    return False


class ConnectionChecker:
    def __init__(self, conn, checks_mode=ChecksMode.WEB):
        self._conn = conn
        self._debug_conn = None
        self._seen_versions = set()
        self._seen_ciphers = dict()
        self._checks_mode = checks_mode
        self._bad_ciphers = set()
        self._phase_out_ciphers = set()
        self._sufficient_ciphers = set()
        self._cipher_order_violation = []

        if self._checks_mode == ChecksMode.WEB:
            self._score_compression_good = scoring.WEB_TLS_COMPRESSION_GOOD
            self._score_compression_bad = scoring.WEB_TLS_COMPRESSION_BAD
            self._score_secure_reneg_good = scoring.WEB_TLS_SECURE_RENEG_GOOD
            self._score_secure_reneg_bad = scoring.WEB_TLS_SECURE_RENEG_BAD
            self._score_client_reneg_good = scoring.WEB_TLS_CLIENT_RENEG_GOOD
            self._score_client_reneg_bad = scoring.WEB_TLS_CLIENT_RENEG_BAD
            self._score_trusted_good = scoring.WEB_TLS_TRUSTED_GOOD
            self._score_trusted_bad = scoring.WEB_TLS_TRUSTED_BAD
            self._score_tls_suites_ok = scoring.WEB_TLS_SUITES_OK
            self._score_tls_suites_bad = scoring.WEB_TLS_SUITES_BAD
            self._score_tls_protocols_good = scoring.WEB_TLS_PROTOCOLS_GOOD
            self._score_tls_protocols_sufficient = scoring.WEB_TLS_PROTOCOLS_GOOD
            self._score_tls_protocols_bad = scoring.WEB_TLS_PROTOCOLS_BAD
            self._score_tls_fs_ok = scoring.WEB_TLS_FS_OK
            self._score_tls_fs_bad = scoring.WEB_TLS_FS_BAD
            self._score_zero_rtt_good = scoring.WEB_TLS_ZERO_RTT_GOOD
            self._score_zero_rtt_bad = scoring.WEB_TLS_ZERO_RTT_BAD
            self._score_ocsp_staping_good = scoring.WEB_TLS_OCSP_STAPLING_GOOD
            self._score_ocsp_staping_ok = scoring.WEB_TLS_OCSP_STAPLING_OK
            self._score_ocsp_staping_bad = scoring.WEB_TLS_OCSP_STAPLING_BAD
            self._score_tls_cipher_order_good = scoring.WEB_TLS_CIPHER_ORDER_GOOD
            self._score_tls_cipher_order_bad = scoring.WEB_TLS_CIPHER_ORDER_BAD
            self._score_tls_kex_hash_func_good = scoring.WEB_TLS_KEX_HASH_FUNC_GOOD
            self._score_tls_kex_hash_func_bad = scoring.WEB_TLS_KEX_HASH_FUNC_BAD
        elif self._checks_mode == ChecksMode.MAIL:
            self._score_compression_good = scoring.MAIL_TLS_COMPRESSION_GOOD
            self._score_compression_bad = scoring.MAIL_TLS_COMPRESSION_BAD
            self._score_secure_reneg_good = scoring.MAIL_TLS_SECURE_RENEG_GOOD
            self._score_secure_reneg_bad = scoring.MAIL_TLS_SECURE_RENEG_BAD
            self._score_client_reneg_good = scoring.MAIL_TLS_CLIENT_RENEG_GOOD
            self._score_client_reneg_bad = scoring.MAIL_TLS_CLIENT_RENEG_BAD
            self._score_trusted_good = scoring.MAIL_TLS_TRUSTED_GOOD
            self._score_trusted_bad = scoring.MAIL_TLS_TRUSTED_BAD
            self._score_tls_suites_ok = scoring.MAIL_TLS_SUITES_OK
            self._score_tls_suites_bad = scoring.MAIL_TLS_SUITES_BAD
            self._score_tls_protocols_good = scoring.MAIL_TLS_PROTOCOLS_GOOD
            self._score_tls_protocols_sufficent = scoring.MAIL_TLS_PROTOCOLS_GOOD
            self._score_tls_protocols_bad = scoring.MAIL_TLS_PROTOCOLS_BAD
            self._score_tls_fs_ok = scoring.MAIL_TLS_FS_OK
            self._score_tls_fs_bad = scoring.MAIL_TLS_FS_BAD
            self._score_zero_rtt_good = scoring.MAIL_TLS_ZERO_RTT_GOOD
            self._score_zero_rtt_bad = scoring.MAIL_TLS_ZERO_RTT_BAD
            # OCSP disabled for mail.
            # self._score_ocsp_staping_good = scoring.MAIL_TLS_OCSP_STAPLING_GOOD
            # self._score_ocsp_staping_ok = scoring.MAIL_TLS_OCSP_STAPLING_OK
            # self._score_ocsp_staping_bad = scoring.MAIL_TLS_OCSP_STAPLING_BAD
            self._score_tls_cipher_order_good = scoring.MAIL_TLS_CIPHER_ORDER_GOOD
            self._score_tls_cipher_order_bad = scoring.MAIL_TLS_CIPHER_ORDER_BAD
            self._score_tls_kex_hash_func_good = scoring.MAIL_TLS_KEX_HASH_FUNC_GOOD
            self._score_tls_kex_hash_func_bad = scoring.MAIL_TLS_KEX_HASH_FUNC_BAD
        else:
            raise ValueError

        self._note_conn_details(self._conn)
        self.record_main_connection()

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.close()

    def record_main_connection(self):
        """
        Records the results of methods called for the main connection
        `self._conn`. These will be used instead of calling these methods
        later. Useful for the mail test where the main connection will be
        shutdown as soon as it is not needed anymore; we don't want parallel
        connections left open and mailservers blocking connections as a result.

        """
        self._conn__get_ssl_version = self._conn.get_ssl_version()
        self._conn__get_certificate_chain_verify_result = self._conn.get_certificate_chain_verify_result()
        self._conn__get_tlsext_status_ocsp_resp = self._conn.get_tlsext_status_ocsp_resp()
        self._conn__is_handshake_completed = self._conn.is_handshake_completed()
        self._conn__get_session = self._conn.get_session()

    @property
    def debug_conn(self):
        # Lazily create a DebugConnection on first access, if needed. The
        # client of this class should use 'with' or .close() when finished with
        # this checker instance in order to clean up any specially created
        # debug connection.
        if not self._debug_conn:
            if isinstance(self._conn, DebugConnection):
                # If the connection is not open, supply a new connection.
                if not self._conn.sock:
                    self._debug_conn = DebugConnection.from_conn(self._conn)
                else:
                    self._debug_conn = self._conn
            elif (isinstance(self._conn, ModernConnection)
                  and self._conn__get_ssl_version == TLSV1_2):
                # Don't waste time trying to connect with DebugConnection as
                # we already know it won't work, that's how we ended up with
                # a TLS 1.2 ModernConnection. The only other time we use
                # ModernConnection is for TLS 1.3, but in that case the initial
                # connection would not be TLS 1.2.
                raise ConnectionHandshakeException()
            else:
                self._debug_conn = DebugConnection.from_conn(self._conn)
        return self._debug_conn

    @debug_conn.setter
    def debug_conn(self, value):
        self._debug_conn = value
        self._note_conn_details(self._debug_conn)

    def close(self):
        if self._debug_conn and self._debug_conn is not self._conn:
            self._debug_conn.safe_shutdown()
            self._debug_conn = None

    def _note_conn_details(self, conn):
        ssl_version = conn.get_ssl_version()
        cipher_name = conn.get_current_cipher_name()
        conn_type = type(conn)

        # create missing dict keys if needed
        # don't use a set of ciphers because we care about the order in which
        # the ciphers were encountered
        self._seen_ciphers.setdefault(ssl_version, dict())
        self._seen_ciphers[ssl_version].setdefault(conn_type, list())

        # note the seen SSL version and cipher name
        self._seen_versions.add(ssl_version)
        ciphers = self._seen_ciphers[ssl_version][conn_type]
        if cipher_name not in ciphers:
            ciphers.append(cipher_name)

        self._note_cipher(cipher_name, conn)

    def _debug_info(self, info):
        if (hasattr(settings, 'ENABLE_VERBOSE_TECHNICAL_DETAILS')
                and settings.ENABLE_VERBOSE_TECHNICAL_DETAILS):
            return ' [reason: {}] '.format(info)
        else:
            return ''

    def _get_seen_ciphers_for_conn(self, conn):
        ssl_version = conn.get_ssl_version()
        conn_type = type(conn)
        return self._seen_ciphers[ssl_version][conn_type]

    def _note_cipher(self, cipher, conn=None):
        ci = cipher_infos.get(cipher, None)
        if ci:
            if ci.sec_level == SecLevel.INSUFFICIENT:
                self._bad_ciphers.add(ci.name)
            elif ci.sec_level == SecLevel.PHASE_OUT:
                self._phase_out_ciphers.add(ci.name)
            elif ci.sec_level == SecLevel.SUFFICIENT:
                self._sufficient_ciphers.add(ci.name)

    def check_cert_trust(self):
        """
        Verify the certificate chain.

        """
        verify_result, _ = self._conn__get_certificate_chain_verify_result
        if verify_result != 0:
            return self._score_trusted_bad, verify_result
        else:
            return self._score_trusted_good, verify_result

    def check_ocsp_stapling(self):
        # This will only work if SNI is in use and the handshake has already
        # been done.
        ocsp_response = self._conn__get_tlsext_status_ocsp_resp
        if ocsp_response is not None and ocsp_response.status == 0:
            try:
                ocsp_response.verify(settings.CA_CERTIFICATES)
                return self._score_ocsp_staping_good, OcspStatus.good
            except OcspResponseNotTrustedError:
                return self._score_ocsp_staping_bad, OcspStatus.not_trusted
            except _nassl.OpenSSLError:
                return self._score_ocsp_staping_bad, OcspStatus.not_trusted
        else:
            return self._score_ocsp_staping_ok, OcspStatus.ok

    def check_secure_reneg(self):
        """
        Check if secure renegotiation is supported.

        Secure renegotiation should be supported, except in TLS 1.3.

        """
        # Although the test is not relevant for TLS 1.3, we're still interested
        # in whether the server has this issue with an earlier TLS version, so
        # we always check with DebugConnection.
        try:
            secure_reneg = self.debug_conn.get_secure_renegotiation_support()
            if secure_reneg:
                secure_reneg_score = self._score_secure_reneg_good
            else:
                secure_reneg_score = self._score_secure_reneg_bad
            return secure_reneg_score, secure_reneg
        except (ConnectionSocketException, ConnectionHandshakeException):
            # TODO: extend to support indicating that we were unable to
            # test in the case of ConnectionSocketException?
            return self._score_secure_reneg_good, True

    def check_client_reneg(self):
        """
        Check if client renegotiation is possible.

        Client renegotiation should not be possible.

        """
        # Although the test is not relevant for TLS 1.3, we're still interested
        # in whether the server has this issue with an earlier TLS version, so
        # we always check with DebugConnection.
        try:
            # this check requires a new connection, otherwise we encounter:
            # error:140940F5:SSL routines:ssl3_read_bytes:unexpected record
            with DebugConnection.from_conn(self._conn, version=SSLV23) as new_conn:
                self._note_conn_details(new_conn)
                # Step 1.
                # Send reneg on open connection
                new_conn.do_renegotiate()
                # Step 2.
                # Connection should now be closed, send 2nd reneg to verify
                new_conn.do_renegotiate()
                # If we are still here, client reneg is supported
                client_reneg_score = self._score_client_reneg_bad
                client_reneg = True
        except (ConnectionSocketException, ConnectionHandshakeException,
                socket.error, _nassl.OpenSSLError, IOError):
            # TODO: extend to support indicating that we were unable to
            # test in the case of ConnectionSocketException?
            client_reneg_score = self._score_client_reneg_good
            client_reneg = False
        return client_reneg_score, client_reneg

    def check_compression(self):
        """
        Check if TLS compression is enabled.

        TLS compression should not be enabled.

        """
        # Although the test is not relevant for TLS 1.3, we're still interested
        # in whether the server has this issue with an earlier TLS version, so
        # we always check with DebugConnection.
        try:
            compression = self.debug_conn.get_current_compression_method() is not None
            if compression:
                compression_score = self._score_compression_bad
            else:
                compression_score = self._score_compression_good
            return compression_score, compression
        except (ConnectionSocketException, ConnectionHandshakeException):
            # TODO: extend to support indicating that we were unable to
            # test in the case of ConnectionSocketException?
            return self._score_compression_good, False

    def check_zero_rtt(self):
        # This check isn't relevant to anything less than TLS 1.3.
        if self._conn__get_ssl_version < TLSV1_3:
            return self._score_zero_rtt_good, ZeroRttStatus.na

        # we require an existing connection, as 0-RTT is only possible with
        # connections after the first so that the SSL session can be re-used.
        # is_handshake_completed() will be false if we didn't complete the
        # connection handshake yet or we subsequently shutdown the connection.
        if not self._conn__is_handshake_completed:
            raise ValueError('0-RTT test without a completed handshake')

        session = self._conn__get_session

        # does the server announce support for early data?
        # assumes that at least some data was already exchanged because, with
        # NGINX at least, get_max_early_data() will be <= 0 if no prior data
        # has been written to and read from the connection even if early data
        # is actually supported.
        if session.get_max_early_data() <= 0:
            return self._score_zero_rtt_good, ZeroRttStatus.good

        # terminate the current connection and re-connect using the previous
        # SSL session details then try and write early data to the connection
        self._conn.safe_shutdown()

        try:
            self._conn.connect(do_handshake_on_connect=False)
            self._conn.set_session(session)
            if self._conn._ssl.get_early_data_status() == 0:
                if self._checks_mode == ChecksMode.WEB:
                    http_client = HTTPSConnection.fromconn(self._conn)
                    http_client.putrequest('GET', '/')
                    http_client.endheaders()
                elif self._checks_mode == ChecksMode.MAIL:
                    self._conn.write(
                        bytes(f"EHLO {settings.SMTP_EHLO_DOMAIN}\r\n", 'ascii'))
                    self._conn.read(4096)

                if (self._conn._ssl.get_early_data_status() == 1 and
                        not self._conn.is_handshake_completed()):
                    self._conn.do_handshake()
                    self._note_conn_details(self._conn)
                    if self._conn._ssl.get_early_data_status() == 2:
                        if self._checks_mode == ChecksMode.MAIL:
                            return self._score_zero_rtt_bad, False
                        elif self._checks_mode == ChecksMode.WEB:
                            # 0-RTT status is bad unless the target responds with
                            # HTTP status code 425 Too Early. See:
                            # https://tools.ietf.org/id/draft-ietf-httpbis-replay-01.html#rfc.section.5.2
                            if http_client.getresponse().status == 425:
                                return self._score_zero_rtt_good, ZeroRttStatus.good
                            else:
                                return self._score_zero_rtt_bad, ZeroRttStatus.bad
        except (ConnectionHandshakeException,
                ConnectionSocketException,
                IOError):
            pass

        # TODO: ensure the handshake is completed ready for the next check that
        # uses this connection?
        return self._score_zero_rtt_good, ZeroRttStatus.good

    def check_protocol_versions(self):
        # Test for TLS 1.1 and TLS 1.0 as these are "phase out" per NCSC 2.0
        # Test for SSL v2 and v3 as these are "insecure" per NCSC 2.0
        prots_good = []
        prots_sufficient = []
        prots_bad = []
        prots_phase_out = []
        prots_score = self._score_tls_protocols_good

        prot_test_configs = [
            (TLSV1_3, 'TLS 1.3', prots_good, self._score_tls_protocols_good),
            (TLSV1_2, 'TLS 1.2', prots_sufficient, self._score_tls_protocols_good),
            (TLSV1_1, 'TLS 1.1', prots_phase_out, self._score_tls_protocols_good),
            (TLSV1,   'TLS 1.0', prots_phase_out, self._score_tls_protocols_good),
            (SSLV3,   'SSL 3.0', prots_bad,       self._score_tls_protocols_bad),
            (SSLV2,   'SSL 2.0', prots_bad,       self._score_tls_protocols_bad),
        ]

        for version, name, prot_set, score in prot_test_configs:
            if version in self._seen_versions:
                # No need to test for this protocol version as we already
                # connected with it.
                connected = True
            else:
                # We already tested TLS 1.3 at the beginning when calling
                # http_fetch(), so we only need to use DebugConnection as it
                # can handle the older protocol versions.
                try:
                    with DebugConnection.from_conn(self._conn, version=version) as new_conn:
                        connected = True
                        self._note_conn_details(new_conn)
                except (ConnectionSocketException,
                        ConnectionHandshakeException):
                    connected = False

            if connected:
                prot_set.append(name)
                prots_score = score

        result_dict = {
            'good': prots_good,
            'sufficient': prots_sufficient,
            'bad': prots_bad,
            'phase_out': prots_phase_out,
        }

        return prots_score, result_dict

    def check_dh_params(self):
        dh_param, ecdh_param = False, False
        dh_ff_p, dh_ff_g = False, False

        try:
            # We have to use DebugConnection because ModernConnection doesn't
            # have the _openssl_str_to_dic() method, but use of custom DH FF
            # groups is not relevant for TLS 1.3/ModernConnection anyway.
            with DebugConnection.from_conn(self._conn, ciphers="DH:DHE:!aNULL") as new_conn:
                self._note_conn_details(new_conn)
                dh_param = new_conn._openssl_str_to_dic(new_conn._ssl.get_dh_param())
                try:
                    dh_ff_p = int(dh_param["prime"], 16)  # '0x...'
                    dh_ff_g = dh_param["generator"].partition(' ')[0]  # 'n (0xn)' or '0xn'
                    dh_ff_g = int(dh_ff_g, 16 if dh_ff_g[0:2] == '0x' else 10)
                    dh_param = dh_param["DH_Parameters"].strip("( bit)")  # '(n bit)'
                except ValueError as e:
                    logger.error(
                        "Unexpected failure to parse DH params "
                        f"{dh_param}' for server '{new_conn.server_name}': "
                        f"reason='{e}'")
                    dh_param = False
        except (ConnectionSocketException,
                ConnectionHandshakeException):
            pass

        try:
            with DebugConnection.from_conn(self._conn, ciphers="ECDH:ECDHE:!aNULL") as new_conn:
                self._note_conn_details(new_conn)
                ecdh_param = new_conn._openssl_str_to_dic(new_conn._ssl.get_ecdh_param())
                try:
                    ecdh_param = ecdh_param["ECDSA_Parameters"].strip("( bit)")
                except ValueError as e:
                    logger.error(
                        "Unexpected failure to parse ECDH params "
                        f"'{ecdh_param}' for server '{new_conn.server_name}': "
                        f"reason='{e}'")
                    ecdh_param = False
        except (ConnectionSocketException,
                ConnectionHandshakeException):
            pass

        fs_bad = []
        fs_phase_out = []

        if dh_ff_p and dh_ff_g:
            if (
                    dh_ff_g == FFDHE_GENERATOR and
                    dh_ff_p in FFDHE_SUFFICIENT_PRIMES):
                pass
            elif (
                    dh_ff_g == FFDHE_GENERATOR and
                    dh_ff_p == FFDHE2048_PRIME):
                fs_phase_out.append("DH-2048{}".format(self._debug_info("weak ff group")))
            else:
                fs_bad.append("DH-{}{}".format(dh_param, self._debug_info("unknown ff group")))
        elif dh_param and int(dh_param) < 2048:
            fs_bad.append("DH-{}{}".format(dh_param, self._debug_info("weak bit length")))
        if ecdh_param and int(ecdh_param) < 224:
            fs_bad.append("ECDH-{}{}".format(ecdh_param, self._debug_info("weak bit length")))

        if len(fs_bad) == 0:
            fs_score = self._score_tls_fs_ok
        else:
            fs_score = self._score_tls_fs_bad

        result_dict = {
            'bad': fs_bad,
            'phase_out': fs_phase_out,
            'dh_param': dh_param,
            'ecdh_param': ecdh_param
        }

        return fs_score, result_dict

    def check_kex_hash_func(self):
        # # Re-connect with explicit signature algorithm preferences and
        # # determine signature related properties of the connection. Only
        # # TLS >= 1.2 support specifying the preferred signature algorithms as
        # # ClientHello extensions (of which SignatureAlgorithm is one) were only
        # # introduced in TLS 1.2. Further, according to the OpenSSL 1.1.1 docs
        # # (see: https://www.openssl.org/docs/man1.1.1/man3/SSL_get_peer_signature_type_nid.html)
        # # calls to get_peer_signature_xxx() are only supported for TLS >= 1.2.
        def sha2_supported_or_na(v, sigalgs):
            # We should have seen all protocol versions by the time this test
            # is executed, so we can avoid a pointless connection attempt if
            # the requested protocol version has not been seen already:
            if v not in self._seen_versions:
                return KexHashFuncStatus.good

            # Unsupported TLS version or ConnectionSocketException or no
            # hash function information available or no common signature
            # algorithm. This could be due to lack of SHA2, but we cannot
            # tell the difference between handshake failure due to lack of
            # SHA2 versus lack of support for a protocol version.
            result = KexHashFuncStatus.unknown

            try:
                # Only ModernConnection supports passing the signature
                # algorithm preference to the server. Don't try to connect
                # using cipher suites that use RSA for key exchange as they
                # have no signature and thus no hash function is used.
                with ModernConnection.from_conn(
                        self._conn, version=v,
                        signature_algorithms=sigalgs) as new_conn:
                    # we were able to connect with the given SHA2 sigalgs
                    self._note_conn_details(new_conn)

                    # Ensure that the requirement in the OpenSSL docs that
                    # the peer has signed a message is satisfied by
                    # exchanging data with the server.
                    if self._checks_mode == ChecksMode.WEB:
                        http_client = HTTPSConnection.fromconn(new_conn)
                        http_client.putrequest('GET', '/')
                        http_client.endheaders()
                        http_client.getresponse()
                    elif self._checks_mode == ChecksMode.MAIL:
                        new_conn.write(bytes(
                            f"EHLO {settings.SMTP_EHLO_DOMAIN}\r\n", 'ascii'))
                        new_conn.read(4096)

                    # From: https://www.openssl.org/docs/man1.1.1/man3/SSL_get_peer_signature_nid.html
                    # "There are several possible reasons for failure:
                    #   1. the cipher suite has no signature (e.g. it uses
                    #      RSA key exchange or is anonymous)
                    #   2. the TLS version is below 1.2 or
                    #   3. the functions were called too early, e.g. before
                    #      the peer signed a message."
                    # We can exclude #2 and #3 as we deliberately make a
                    # TLS 1.2 connection and exchange messages with the
                    # server, so failure must be because "the cipher suite
                    # has no signature" in which case there is no hash
                    # function to check. In my testing only ciphers that
                    # use RSA for key exchange caused the None value to be
                    # returned, i.e. case #1.
                    kex_hash_func = new_conn.get_peer_signature_digest()
                    if kex_hash_func:
                        if kex_hash_func in KEX_GOOD_HASH_FUNCS:
                            result = KexHashFuncStatus.good
                        else:
                            result = KexHashFuncStatus.bad
            except ValueError as e:
                # The NaSSL library can raise ValueError if the given
                # sigalgs value is unable to be set in the underlying
                # OpenSSL library.
                if str(e) == 'Invalid or unsupported signature algorithm':
                    # This is an unexpected internal error, not a problem
                    # with the target server. Log it and continue.
                    logger.warning(
                        f"Unexpected ValueError '{e}' while setting "
                        f"client sigalgs to '{sigalgs}' when attempting "
                        f"to test which key exchange SHA2 hash functions "
                        f"target server '{self._conn.server_name}' "
                        f"supports with TLS version {v.name}")
                    pass
                else:
                    raise e
            except ConnectionHandshakeException:
                # So we've been able to connect earlier with this TLS
                # version but now as soon as we restrict ourselves to
                # certain SHA2 hash functions the handshake fails, implying
                # that the server does not support them.
                result = KexHashFuncStatus.bad
            except ConnectionSocketException:
                # TODO: extend to support indicating that we were unable to
                # test in the case of ConnectionSocketException?
                pass

            return result

        # Older SSL/TLS protocol versions only supported MD5 and SHA1:
        # From: https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
        # ---------------------------------------------------------------------
        # If the client does not send the signature_algorithms extension, the
        # server MUST do the following:
        #
        # -  If the negotiated key exchange algorithm is one of (RSA, DHE_RSA,
        #     DH_RSA, RSA_PSK, ECDH_RSA, ECDHE_RSA), behave as if client had
        #     sent the value {sha1,rsa}.
        #
        # -  If the negotiated key exchange algorithm is one of (DHE_DSS,
        #     DH_DSS), behave as if the client had sent the value {sha1,dsa}.
        #
        # -  If the negotiated key exchange algorithm is one of (ECDH_ECDSA,
        #     ECDHE_ECDSA), behave as if the client had sent value {sha1,ecdsa}.
        #
        # Note: this is a change from TLS 1.1 where there are no explicit
        # rules, but as a practical matter one can assume that the peer
        # supports MD5 and SHA-1.
        #
        # Note: this extension is not meaningful for TLS versions prior to 1.2.
        # Clients MUST NOT offer it if they are offering prior versions.
        # ---------------------------------------------------------------------
        newest_seen_tls_version = sorted(self._seen_versions, reverse=True)[0]
        # To be considered to have a good key exchange hash function
        # you've got to be using at least TLS 1.2:
        if newest_seen_tls_version >= TLSV1_2:
            # Check TLS 1.3 SHA2 support:
            result_tls13 = sha2_supported_or_na(
                TLSV1_3, KEX_TLS13_SHA2_SIGALG_PREFERENCE)
            # TLS 1.3 without SHA2 is bad, otherwise...
            if result_tls13 != KexHashFuncStatus.bad:
                # Check TLS 1.2 SHA2 support:
                result_tls12 = sha2_supported_or_na(
                    TLSV1_2, KEX_TLS12_SHA2_SIGALG_PREFERENCE)
                # If the available protocols > TLS 1.2 all support SHA2 for
                # key exchange then that's good.
                if (
                        result_tls13 == KexHashFuncStatus.good and
                        result_tls12 == KexHashFuncStatus.good):
                    return self._score_tls_kex_hash_func_good, KexHashFuncStatus.good
                # But if we're unable to determine conclusively one way or the
                # other for either TLS 1.2 or TLS 1.3, then don't penalize the
                # server but do indicate that uncertain situation.
                elif (result_tls13 == KexHashFuncStatus.unknown or
                      result_tls12 == KexHashFuncStatus.unknown):
                    return self._score_tls_kex_hash_func_good, KexHashFuncStatus.unknown

        # Otherwise at least one of TLS 1.2 and/or TLS 1.3 lacks support for
        # SHA2 for key exchange which is bad.
        return self._score_tls_kex_hash_func_bad, KexHashFuncStatus.bad

    def _check_sec_score_order(self, lowest_values, curr_cipher, new_conn):
        """
        Check for compliance with NCSC 2.0 prescribed ordering.

        """
        # If we already have a security level violation return.
        if (self._cipher_order_violation
                and self._cipher_order_violation[2] == ''):
            return

        ci = cipher_infos.get(curr_cipher, None)
        score = (
            CipherScoreAndSecLevel.calc_cipher_score(ci, new_conn)
            if ci else None)
        seclevel = (
            CipherScoreAndSecLevel.determine_appendix_c_sec_level(ci)
            if ci else None)

        if not self._cipher_order_violation:
            if score:
                if (lowest_values['score'] and not
                        CipherScoreAndSecLevel.is_in_prescribed_order(
                            lowest_values['score'], score)):
                    rule = CipherScoreAndSecLevel.get_violated_rule_number(
                        score, lowest_values['score'])
                    self._cipher_order_violation = [
                        lowest_values['score_cipher'], curr_cipher, rule]
                else:
                    lowest_values['score'] = score
                    lowest_values['score_cipher'] = curr_cipher

        if (not self._cipher_order_violation
                or self._cipher_order_violation[2] != ''):
            # There may be already a score violation but security level trumps
            # score.
            if seclevel:
                if (lowest_values['seclevel'] and not
                        CipherScoreAndSecLevel.is_in_seclevel_order(
                            lowest_values['seclevel'], seclevel)):
                    self._cipher_order_violation = [
                        lowest_values['seclevel_cipher'], curr_cipher, '']
                else:
                    lowest_values['seclevel'] = seclevel
                    lowest_values['seclevel_cipher'] = curr_cipher

    def _check_ciphers(self, test_config, first_cipher_only=False):
        done = False
        for conn_type, tls_version, cipher_string in test_config:
            if done:
                break
            # Exclude ciphers we've already seen for this connection handler
            relevant_ciphers = self._seen_ciphers.get(tls_version, dict()).get(
                conn_type, frozenset())
            reject_string = ':'.join([f'!{x}' for x in relevant_ciphers])
            if reject_string:
                cipher_string = f"{reject_string}:{cipher_string}"

            lowest_values = {
                'score': None,
                'score_cipher': None,
                'seclevel': None,
                'seclevel_cipher': None,
            }

            last_cipher = None
            while True:
                try:
                    with conn_type.from_conn(
                            self._conn, ciphers=cipher_string,
                            version=tls_version) as new_conn:

                        # record the cipher details and add the cipher to the
                        # insufficient or phase out sets.
                        self._note_conn_details(new_conn)

                        # ensure we don't get stuck in an infinite loop.
                        curr_cipher = new_conn.get_current_cipher_name()
                        if curr_cipher == last_cipher:
                            logger.warning(
                                'Infinite loop breakout in '
                                'check_cipher_sec_level '
                                f'with cipher {curr_cipher}, '
                                f'protocol {new_conn.get_ssl_version().name}, '
                                f'server {new_conn.server_name}')
                            break

                        self._check_sec_score_order(
                            lowest_values, curr_cipher, new_conn)

                        # Update the cipher string to exclude the current
                        # cipher (not cipher suite) from the cipher suite
                        # negotiation on the next connection.
                        cipher_string = f"!{curr_cipher}:{cipher_string}"

                        last_cipher = curr_cipher
                except (ConnectionSocketException,
                        ConnectionHandshakeException):
                    break

                # When checking SMTP servers only check for one bad cipher.
                if self._checks_mode == ChecksMode.MAIL or first_cipher_only:
                    done = True
                    break

    def check_cipher_order(self):
        """
        Check whether the server enforces its own cipher order or if that
        order can be overriden by the client.

        Also complete the prescribed order check: if
        `self.check_cipher_sec_level()` found no violations in phase out or
        insufficient ciphers, and IFF the server enforces its own cipher order,
        then also test the order that "good" ciphers are selected by the
        server.

        """
        def _get_nth_or_default(collection, index, default):
            return collection[index] if index < len(collection) else default

        def _get_another_cipher(self, ignore_ciphers):
            try:
                if self._conn__get_ssl_version < TLSV1_3:
                    with self._conn.dup(
                            cipher_list_action=CipherListAction.PREPEND,
                            ciphers=':'.join(
                                [f'!{cipher}' for cipher in ignore_ciphers])
                            ) as new_conn:
                        self._note_conn_details(new_conn)
                        another_cipher = new_conn.get_current_cipher_name()
                else:
                    # OpenSSL 1.1.1 TLS 1.3 cipher preference strings do not
                    # support '!' thus we must instead manually exclude the
                    # current cipher using the known small set of allowed TLS
                    # 1.3 ciphers. See '-ciphersuites' at:
                    #   https://www.openssl.org/docs/man1.1.1/man1/ciphers.html
                    remaining_ciphers = set(
                        ModernConnection.ALL_TLS13_CIPHERS.split(':'))
                    remaining_ciphers.difference_update(ignore_ciphers)
                    cipher_string = ':'.join(remaining_ciphers)
                    with self._conn.dup(tls13ciphers=cipher_string) as new_conn:
                        self._note_conn_details(new_conn)
                        another_cipher = new_conn.get_current_cipher_name()
            except ConnectionHandshakeException:
                another_cipher = None
            return another_cipher

        cipher_order_score = self._score_tls_cipher_order_good
        cipher_order = CipherOrderStatus.good

        # Check specifically for SUFFICIENT cipher support.
        self._check_ciphers([
            (DebugConnection,  SSLV23, ':'.join(SUFFICIENT_DEBUG_CIPHERS)),
            (ModernConnection, SSLV23, ':'.join(SUFFICIENT_MODERN_CIPHERS)),
        ], first_cipher_only=True)
        # If the server only supports GOOD ciphers we don't care
        # about the cipher order.
        if not (self._bad_ciphers or self._phase_out_ciphers or
                self._sufficient_ciphers):
            self._cipher_order_violation = []
            return (
                cipher_order_score, CipherOrderStatus.na,
                self._cipher_order_violation)

        # For this test we need two ciphers, one selected by the server and
        # another selected by the server when the former was disallowed by the
        # client. We then reverse the order of these two ciphers in the list of
        # ciphers that the client tells the server it supports, and see if the
        # server still selects the same cipher. We hope that the server doesn't
        # consider both ciphers to be of equal weight and thus happy to use
        # either irrespective of order.

        # Which ciphers seen so far during checks are relevant for self._conn?
        relevant_ciphers = self._get_seen_ciphers_for_conn(self._conn)

        # Get the cipher name of at least one cipher that works with self._conn
        first_cipher = relevant_ciphers[0]
        ignore_ciphers = [first_cipher]
        second_cipher = _get_nth_or_default(
            relevant_ciphers, 1, _get_another_cipher(self, ignore_ciphers))

        # Try to get a non CHACHA cipher to avoid the possible
        # PRIORITIZE_CHACHA server option.
        # https://github.com/NLnetLabs/Internet.nl/issues/461
        while second_cipher:
            ci = cipher_infos.get(second_cipher, None)
            if ci and "CHACHA" not in ci.bulk_enc_alg:
                break
            ignore_ciphers.append(second_cipher)
            second_cipher = _get_another_cipher(self, ignore_ciphers)

        if second_cipher and first_cipher != second_cipher:
            try:
                # Now that we know of two ciphers that can be used to connect
                # to the server, one of which was chosen in preference to the
                # other, ask the server to use them in reverse order and
                # confirm that the server instead continues to impose its own
                # order preference on the cipher selection process:
                cipher_string = f'{second_cipher}:{first_cipher}'
                if self._conn__get_ssl_version < TLSV1_3:
                    with self._conn.dup(ciphers=cipher_string) as new_conn:
                        self._note_conn_details(new_conn)
                        newly_selected_cipher = new_conn.get_current_cipher_name()
                else:
                    with self._conn.dup(tls13ciphers=cipher_string) as new_conn:
                        self._note_conn_details(new_conn)
                        newly_selected_cipher = new_conn.get_current_cipher_name()

                if newly_selected_cipher == second_cipher:
                    cipher_order_score = self._score_tls_cipher_order_bad
                    cipher_order = CipherOrderStatus.bad

            except ConnectionHandshakeException:
                # Unable to connect with reversed cipher order.
                pass

        # Did a previous call to self.check_cipher_sec_level() discover a
        # prescribed order violation?
        if not (cipher_order == CipherOrderStatus.bad
                or self._cipher_order_violation):
            # Complete the prescribed order check by testing "good" ciphers.
            # and "sufficient" ciphers.
            self._check_ciphers([
                (DebugConnection,  SSLV23, ':'.join(GOOD_SUFFICIENT_DEBUG_CIPHERS)),
                (ModernConnection, SSLV23, ':'.join(GOOD_SUFFICIENT_MODERN_CIPHERS)),
            ])

        # The self._cipher_order_violation list will be populated if the
        # call to self._check_ciphers() finds a prescribed order violation.

        if cipher_order == CipherOrderStatus.bad:
            # Server does not respect its own preference; ignore any order
            # violation.
            pass
        elif self._cipher_order_violation:
            if self._cipher_order_violation[2] == '':
                cipher_order = CipherOrderStatus.not_seclevel
                cipher_order_score = self._score_tls_cipher_order_bad
            else:
                cipher_order = CipherOrderStatus.not_prescribed

        return cipher_order_score, cipher_order, self._cipher_order_violation

    def check_cipher_sec_level(self):
        """
        Check whether ciphers selected by the server are phase out or
        insufficient according to the rules set out in the NCSC "IT Security
        Guidelines for Transport Layer Security (TLS) v2.0" document.

        This is done by connecting with the "bad" TLS cipher suites then
        re-connecting minus the last connected cipher. Ciphers that have
        already been seen in other ConnectionChecker checks are excluded. This
        is because the actual work of recording which ciphers are phase out or
        insufficient is done by `self._note_cipher()`, whether in this check or
        an earlier check, thus avoiding unnecessary connections with ciphers
        that have already been seen.

        As the prescribed order check also involves visiting lots of ciphers in
        server order part of the prescribed order check is done in this check.
        The check is completed and the result returned by
        `self.check_cipher_order()` (both to better group logically related
        results and because if no violation is detected in this check it may
        still be the case that "Good" ciphers violate the check, but there's no
        reason to check those if the server cipher order check fails).

        Note: We do NOT test TLS 1.3 ciphers as these are "good" (when
        excluding negotiated properites, such as the hash function, as per NCSC
        v2.0 TLS "Appendix C - List of cipher suites").

        """
        ciphers_score = self._score_tls_suites_ok

        self._check_ciphers([
            (DebugConnection,  SSLV23,  ':'.join(PHASE_OUT_CIPHERS+INSUFFICIENT_CIPHERS)),
            (DebugConnection,  SSLV2,   ':'.join(INSUFFICIENT_CIPHERS_SSLV2)),
            (ModernConnection, SSLV23, ':'.join(PHASE_OUT_CIPHERS_MODERN+INSUFFICIENT_CIPHERS_MODERN)),
        ])

        if self._bad_ciphers:
            ciphers_score = self._score_tls_suites_bad
        elif self._phase_out_ciphers:
            ciphers_score = self._score_tls_suites_ok

        result_dict = {
            'bad': list(self._bad_ciphers),
            'phase_out': list(self._phase_out_ciphers)
        }

        return ciphers_score, result_dict


def check_web_tls(url, af_ip_pair=None, *args, **kwargs):
    """
    Check the webserver's TLS configuration.

    """

    def connect_to_web_server():
        http_client, *_ = http_fetch(
            url, af=af_ip_pair[0], path="", port=443, ip_address=af_ip_pair[1],
            depth=MAX_REDIRECT_DEPTH, task=web_conn, keep_conn_open=True)
        return http_client.conn

    try:
        # connect with the higest possible TLS version assuming that the server
        # responds to HTTP requests, then check some interesting properties of
        # this 'best possible' connection.
        with connect_to_web_server() as conn:
            with ConnectionChecker(conn, ChecksMode.WEB) as checker:
                # Note: additional connections will be created by the checker
                # as needed. The order of the checks attempts to benefit from
                # data acquired during previous checks.
                ocsp_stapling_score, ocsp_stapling = checker.check_ocsp_stapling()
                secure_reneg_score, secure_reneg = checker.check_secure_reneg()
                client_reneg_score, client_reneg = checker.check_client_reneg()
                compression_score, compression = checker.check_compression()
                ciphers_score, ciphers_result = checker.check_cipher_sec_level()
                zero_rtt_score, zero_rtt = checker.check_zero_rtt()
                prots_score, prots_result = checker.check_protocol_versions()
                fs_score, fs_result = checker.check_dh_params()
                kex_hash_func_score, kex_hash_func = checker.check_kex_hash_func()
                cipher_order_score, cipher_order, cipher_order_violation = checker.check_cipher_order()

        return dict(
            tls_enabled=True,
            prots_bad=prots_result['bad'],
            prots_phase_out=prots_result['phase_out'],
            prots_good=prots_result['good'],
            prots_sufficient=prots_result['sufficient'],
            prots_score=prots_score,

            ciphers_bad=ciphers_result['bad'],
            ciphers_phase_out=ciphers_result['phase_out'],
            ciphers_score=ciphers_score,
            cipher_order_score=cipher_order_score,
            cipher_order=cipher_order,
            cipher_order_violation=cipher_order_violation,

            secure_reneg=secure_reneg,
            secure_reneg_score=secure_reneg_score,
            client_reneg=client_reneg,
            client_reneg_score=client_reneg_score,
            compression=compression,
            compression_score=compression_score,

            dh_param=fs_result['dh_param'],
            ecdh_param=fs_result['ecdh_param'],
            fs_bad=fs_result['bad'],
            fs_phase_out=fs_result['phase_out'],
            fs_score=fs_score,

            zero_rtt_score=zero_rtt_score,
            zero_rtt=zero_rtt,

            ocsp_stapling=ocsp_stapling,
            ocsp_stapling_score=ocsp_stapling_score,

            kex_hash_func=kex_hash_func,
            kex_hash_func_score=kex_hash_func_score,
        )
    except (socket.error, NoIpError, ConnectionSocketException):
        return dict(server_reachable=False, tls_enabled=False)
    except (http.client.BadStatusLine, ConnectionHandshakeException):
        return dict(tls_enabled=False)


def do_web_http(af_ip_pairs, url, task, *args, **kwargs):
    """
    Start all the HTTP related checks for the web test.

    """
    try:
        results = {}
        for af_ip_pair in af_ip_pairs:
            results[af_ip_pair[1]] = http_checks(af_ip_pair, url, task)

    except SoftTimeLimitExceeded:
        for af_ip_pair in af_ip_pairs:
            if not results.get(af_ip_pair[1]):
                results[af_ip_pair[1]] = dict(
                    forced_https=False,
                    forced_https_score=scoring.WEB_TLS_FORCED_HTTPS_BAD,
                    http_compression_enabled=True,
                    http_compression_score=(
                        scoring.WEB_TLS_HTTP_COMPRESSION_BAD),
                    hsts_enabled=False,
                    hsts_policies=[],
                    hsts_score=scoring.WEB_TLS_HSTS_BAD,
                )

    return ('http_checks', results)


def http_checks(af_ip_pair, url, task):
    """
    Perform the HTTP header and HTTPS redirection checks for this webserver.

    """
    forced_https_score, forced_https = forced_http_check(af_ip_pair, url, task)
    header_checkers = [
        HeaderCheckerContentEncoding(),
        HeaderCheckerStrictTransportSecurity(),
    ]
    header_results = http_headers_check(af_ip_pair, url, header_checkers, task)

    results = {
        'forced_https': forced_https,
        'forced_https_score': forced_https_score,
    }
    results.update(header_results)
    return results


def forced_http_check(af_ip_pair, url, task):
    """
    Check if the webserver is properly configured with HTTPS redirection.

    """
    # First connect on port 80 and see if we get refused
    try:
        has_443 = False
        conn, res, headers, visited_hosts = http_fetch(
            url, af=af_ip_pair[0], path="", port=443, task=task,
            ip_address=af_ip_pair[1],
            depth=MAX_REDIRECT_DEPTH)
        has_443 = True
        conn, res, headers, visited_hosts = http_fetch(
            url, af=af_ip_pair[0], path="", port=80, task=task,
            ip_address=af_ip_pair[1])
    except (socket.error, http.client.BadStatusLine, NoIpError,
            ConnectionHandshakeException, ConnectionSocketException):
        if has_443:
            # If we got refused on port 80 the first time
            # return the FORCED_HTTPS_NO_HTTP status and score
            return scoring.WEB_TLS_FORCED_HTTPS_NO_HTTP, ForcedHttpsStatus.no_http
        else:
            # No connection anywhere; return failure.
            return scoring.WEB_TLS_FORCED_HTTPS_BAD, ForcedHttpsStatus.bad

    # Valid if same domain, or *higher* domain. Use case:
    # www.example.com:80 -> example.com:443. Example.com:443 can set HSTS
    # with includeSubdomains
    forced_https = ForcedHttpsStatus.bad
    forced_https_score = scoring.WEB_TLS_FORCED_HTTPS_BAD

    if 443 in visited_hosts and conn.port == 443:
        for visited_host in visited_hosts[443]:
            if visited_host in url:
                forced_https = ForcedHttpsStatus.good
                forced_https_score = scoring.WEB_TLS_FORCED_HTTPS_GOOD
                break

    return forced_https_score, forced_https
