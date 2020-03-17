# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import re

from ..models import BatchRequestType, DmarcPolicyStatus
from ..scoring import STATUS_SUCCESS
from ..tasks.tls import has_daneTA


def get_applicable_views(user, batch_request):
    views = []
    user_views = user.custom_views.all()
    for custom_view in user_views:
        view_class = VIEWS_MAP.get(custom_view.name)
        if not view_class:
            break

        if view_class.is_applicable(batch_request):
            views.append(view_class)
    return views


def gather_views_results(views, batch_domain, batch_request_type):
    """
    Return the results for the given views.

    """
    results = []
    if not views:
        return results

    for view in views:
        result = view.get_view_data(batch_request_type, batch_domain)
        if result:
            if isinstance(result, list):
                results.extend(result)
            else:
                results.append(result)
    return results


def _camel_case_to_snake(string):
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', string)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


class CustomView(object):
    """
    Base class for custom views.

    The `self.settings` keys dictate if the view is applicable in web and mail
    tests. Further settings per view can be defined in those keys or directly
    under `self.settings`.

    .. note:: The class name of the custom views must be CamelCase and the last
              word must be `View`. Every new custom view must have a docstring
              that will be used as description in the database.

    """
    def __init__(self):
        self.view_id = None
        self.name = self._class_name_to_snake()
        self.setup()

    def setup(self):
        self.settings = {
            BatchRequestType.web: {},
            BatchRequestType.mail: {}
        }

    def is_applicable(self, batch_request):
        """
        Check if the view should be applied based on the test type.

        """
        if batch_request.type in self.settings:
            return True
        return False

    def get_view_data(self, batch_request_type, batch_domain):
        return None

    def get_group_result_from_report(self, batch_domain, batch_request_type):
        """
        Check all the report_items in the report for SUCCESS.

        """
        result = True
        batch_test = batch_domain.get_batch_test()
        report = getattr(
            batch_test.report, self.settings['report_model']).report
        report_items = self.settings[batch_request_type]['report_items']
        for report_item in report_items:
            if not report.get(report_item):
                result = False
                break
            elif report[report_item]['status'] != STATUS_SUCCESS:
                result = False
                break
        return result

    def get_raw_data_from_reports(self, batch_domain, batch_request_type):
        """
        Get the raw reports for this domain.

        .. note:: This is not a True/False view.

        """
        result = {}
        batch_test = batch_domain.get_batch_test()
        for category in self.settings[batch_request_type]['test_categories']:
            report = getattr(batch_test.report, category).report
            result[category] = report
        return result

    def _class_name_to_snake(self):
        """
        Convert the class name from camel-case to snake-case while removing
        the 'View' part.

        """
        name = self.__class__.__name__.replace("View", "")
        return _camel_case_to_snake(name)


class TlsAvailableView(CustomView):
    """
    View to check if TLS is available.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'https_exists',
                ]
            },
            BatchRequestType.mail: {
                'report_items': [
                    'starttls_exists',
                ]
            },
            'report_model': 'tls',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class TlsNcscWebView(CustomView):
    """
    View to check if TLS follows the NCSC's guidelines.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'https_exists',
                    'fs_params',
                    'tls_ciphers',
                    'tls_version',
                    'tls_compression',
                    'renegotiation_secure',
                    'renegotiation_client',
                    'cert_trust',
                    'cert_pubkey',
                    'cert_signature',
                    'cert_hostmatch',
                ]
            },
            'report_model': 'tls',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class Ipv6NameserverView(CustomView):
    """
    View to check addresses and reachability of nameservers.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'ns_aaaa',
                    'ns_reach',
                ]},
            BatchRequestType.mail: {
                'report_items': [
                    'ns_aaaa',
                    'ns_reach',
                ]},
            'report_model': 'ipv6',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class Ipv6WebserverView(CustomView):
    """
    View to check addresses, reachability and IPv4/6 difference of the
    webserver.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'web_aaaa',
                    'web_reach',
                    'web_ipv46',
                ]},
            'report_model': 'ipv6',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class Ipv6MailserverView(CustomView):
    """
    View to check addresses and reachability of mailservers.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.mail: {
                'report_items': [
                    'mx_aaaa',
                    'mx_reach',
                ]},
            'report_model': 'ipv6',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class DnssecEmailDomainView(CustomView):
    """
    View to check the existence and validity of DNSSEC on the email address
    domain.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.mail: {
                'report_items': [
                    'dnssec_exists',
                    'dnssec_valid',
                ]},
            'report_model': 'dnssec',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class DnssecMailserverDomainView(CustomView):
    """
    View to check the existence and validity of DNSSEC on the mailserver
    domain.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.mail: {
                'report_items': [
                    'dnssec_mx_exists',
                    'dnssec_mx_valid',
                ]},
            'report_model': 'dnssec',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class HttpsEnforcedView(CustomView):
    """
    View to check if HTTPS enforcement is in place.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'https_forced',
                ]},
            'report_model': 'tls',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class HstsView(CustomView):
    """
    View to check if HSTS is available.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'https_hsts',
                ]},
            'report_model': 'tls',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class DaneView(CustomView):
    """
    View to check existence and validity of DANE.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'dane_exists',
                    'dane_valid',
                ]},
            BatchRequestType.mail: {
                'report_items': [
                    'dane_exists',
                    'dane_valid',
                ]},
            'report_model': 'tls',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class DmarcView(CustomView):
    """
    View to check if DMARC is available.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.mail: {}
        }

    def get_view_data(self, batch_request_type, batch_domain):
        batch_test = batch_domain.get_batch_test()
        result = batch_test.auth.dmarc_available
        return dict(name=self.name, result=result)


class DkimView(CustomView):
    """
    View to check if DKIM is available.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.mail: {}
        }

    def get_view_data(self, batch_request_type, batch_domain):
        batch_test = batch_domain.get_batch_test()
        result = batch_test.auth.dkim_available
        return dict(name=self.name, result=result)


class SpfView(CustomView):
    """
    View to check if SPF is available.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.mail: {}
        }

    def get_view_data(self, batch_request_type, batch_domain):
        batch_test = batch_domain.get_batch_test()
        result = batch_test.auth.spf_available
        return dict(name=self.name, result=result)


class RawReportsView(CustomView):
    """
    View to return the raw data from the reports.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'test_categories': ['ipv6', 'dnssec', 'tls', 'appsecpriv']
            },
            BatchRequestType.mail: {
                'test_categories': ['ipv6', 'dnssec', 'auth', 'tls']
            }
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_raw_data_from_reports(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class ForumStandaardisatieView(CustomView):
    """
    View specified by Forum Standaardisatie.
    It gets the specified results from a mail or web report and returns them
    mapped to a specified name.

    """
    def setup(self):
        self.view_id = '20190524_FS'
        self.settings = {
            BatchRequestType.web: {
                'ipv6': {
                    'ns_aaaa': 'web_ipv6_ns_address',
                    'ns_reach': 'web_ipv6_ns_reach',
                    'web_aaaa': 'web_ipv6_ws_address',
                    'web_reach': 'web_ipv6_ws_reach',
                    'web_ipv46': 'web_ipv6_ws_similar',
                },
                'dnssec': {
                    'dnssec_exists': 'web_dnssec_exist',
                    'dnssec_valid': 'web_dnssec_valid',
                },
                'tls': {
                    'https_exists': 'web_https_http_available',
                    'https_forced': 'web_https_http_redirect',
                    'https_hsts': 'web_https_http_hsts',
                    'http_compression': 'web_https_http_compress',
                    'tls_version': 'web_https_tls_version',
                    'tls_ciphers': 'web_https_tls_ciphers',
                    'fs_params': 'web_https_tls_keyexchange',
                    'tls_compression': 'web_https_tls_compress',
                    'renegotiation_secure': 'web_https_tls_secreneg',
                    'renegotiation_client': 'web_https_tls_clientreneg',
                    'cert_trust': 'web_https_cert_chain',
                    'cert_pubkey': 'web_https_cert_pubkey',
                    'cert_signature': 'web_https_cert_sig',
                    'cert_hostmatch': 'web_https_cert_domain',
                    'dane_exists': 'web_https_dane_exist',
                    'dane_valid': 'web_https_dane_valid',
                },
                'appsecpriv': {
                    'http_x_frame': 'web_appsecpriv_x_frame_options',
                    'http_x_content_type': 'web_appsecpriv_x_content_type_options',
                    'http_x_xss': 'web_appsecpriv_x_xss_protection',
                    'http_csp': 'web_appsecpriv_csp',
                    'http_referrer_policy': 'web_appsecpriv_referrer_policy',
                },
            },
            BatchRequestType.mail: {
                'ipv6': {
                    'ns_aaaa': 'mail_ipv6_ns_address',
                    'ns_reach': 'mail_ipv6_ns_reach',
                    'mx_aaaa': 'mail_ipv6_mx_address',
                    'mx_reach': 'mail_ipv6_mx_reach',
                },
                'dnssec': {
                    'dnssec_exists': 'mail_dnssec_mailto_exist',
                    'dnssec_valid': 'mail_dnssec_mailto_valid',
                    'dnssec_mx_exists': 'mail_dnssec_mx_exist',
                    'dnssec_mx_valid': 'mail_dnssec_mx_valid',
                },
                'auth': {
                    'dkim': 'mail_auth_dkim_exist',
                    'dmarc': 'mail_auth_dmarc_exist',
                    'dmarc_policy': 'mail_auth_dmarc_policy',
                    'spf': 'mail_auth_spf_exist',
                    'spf_policy': 'mail_auth_spf_policy',
                },
                'tls': {
                    'starttls_exists': 'mail_starttls_tls_available',
                    'tls_version': 'mail_starttls_tls_version',
                    'tls_ciphers': 'mail_starttls_tls_ciphers',
                    'fs_params': 'mail_starttls_tls_keyexchange',
                    'tls_compression': 'mail_starttls_tls_compress',
                    'renegotiation_secure': 'mail_starttls_tls_secreneg',
                    'renegotiation_client': 'mail_starttls_tls_clientreneg',
                    'cert_trust': 'mail_starttls_cert_chain',
                    'cert_pubkey': 'mail_starttls_cert_pubkey',
                    'cert_signature': 'mail_starttls_cert_sig',
                    'cert_hostmatch': 'mail_starttls_cert_domain',
                    'dane_exists': 'mail_starttls_dane_exist',
                    'dane_valid': 'mail_starttls_dane_valid',
                    'dane_rollover': 'mail_starttls_dane_rollover',
                },
            },
        }

    def _get_dmarc_extra_info(self, batch_domain, view_data):
        """
        Extra information on the DMARC test.

        """
        batch_test = batch_domain.get_batch_test()
        dmarc_policy_status = batch_test.auth.dmarc_policy_status

        policy_only = False
        if dmarc_policy_status in (
                DmarcPolicyStatus.valid, DmarcPolicyStatus.invalid_external):
            policy_only = True
        view_data.append(dict(
            name='mail_auth_dmarc_policy_only',
            result=policy_only))

        ext_dest = False
        if dmarc_policy_status == DmarcPolicyStatus.valid:
            ext_dest = True
        view_data.append(dict(
            name='mail_auth_dmarc_ext_destination',
            result=ext_dest))

    def _get_starttls_extra_info(self, batch_domain, view_data):
        """
        Extra information on the STARTTLS test.

        """
        batch_test = batch_domain.get_batch_test()
        report = batch_test.tls.report

        server_configured = True
        if report['starttls_exists']['verdict'] == 'detail mail tls starttls-exists verdict other-2':
            server_configured = False
        view_data.append(dict(
            name='mail_server_configured',
            result=server_configured))

        servers_testable = True
        servers_data = report['starttls_exists']['tech_data']
        if isinstance(servers_data, list):
            for server_name, verdict in servers_data:
                if verdict == 'detail tech data not-tested':
                    servers_testable = False
                    break
        else:
            verdict = servers_data
            if verdict == 'detail tech data not-tested':
                servers_testable = False
        view_data.append(dict(
            name='mail_servers_testable',
            result=servers_testable))

        starttls_dane_ta = False
        if (report['dane_exists']['status'] == STATUS_SUCCESS
                and report['dane_valid']['status'] == STATUS_SUCCESS):
            starttls_dane_ta = True
            tech_data = report['dane_exists']['tech_data']
            for domain, tlsa_records in tech_data:
                if not has_daneTA(tlsa_records):
                    starttls_dane_ta = False
                    break
        view_data.append(dict(
            name='mail_starttls_dane_ta',
            result=starttls_dane_ta))

        non_sending_domain = False
        dmarc_re = re.compile(r'v=DMARC1;\ *p=reject;?')
        spf_re = re.compile(r'v=spf1\ +-all;?')
        dmarc_available = batch_test.auth.dmarc_available
        dmarc_record = batch_test.auth.dmarc_record
        spf_available = batch_test.auth.spf_available
        spf_record = batch_test.auth.spf_record
        if (dmarc_available and spf_available
                and len(dmarc_record) == 1 and len(spf_record) == 1
                and dmarc_re.match(dmarc_record[0])
                and spf_re.fullmatch(spf_record[0])):
            non_sending_domain = True
        view_data.append(dict(
            name='mail_non_sending_domain',
            result=non_sending_domain))

    def get_view_data(self, batch_request_type, batch_domain):
        """
        For each test item specified in the settings above check if the test
        passed and return the result based on the name mapping provided in the
        settings above.

        """
        view_data = []
        batch_test = batch_domain.get_batch_test()
        for report_model, name_mappings in self.settings[batch_request_type].items():
            report = getattr(batch_test.report, report_model).report
            for item, data in report.items():
                if name_mappings.get(item):
                    view_data.append(dict(
                        name=name_mappings[item],
                        result=data['status'] == STATUS_SUCCESS))
        if batch_request_type == BatchRequestType.mail:
            self._get_dmarc_extra_info(batch_domain, view_data)
            self._get_starttls_extra_info(batch_domain, view_data)
        return view_data


class ForumStandaardisatieNewView(ForumStandaardisatieView):
    """
    New version of the Forum Standaardisatie view.
    It creates fields per verdict per subtest and returns them mapped to those
    verdict identifiers. Only one verditct can be true per subtest.
    It would be easier for users to group and understand the API results before
    the API output overhaul.

    """
    def _gather_tests_verdicts_categories(self):
        """
        This populates self.tests with all available verdicts and statuses per
        subtest.

        """
        import inspect
        from ..probes import webprobes, mailprobes
        testname_regex = re.compile(
            r'^detail ([^\s]+ [^\s]+ [^\s]+) label$',
            flags=re.I)
        verdict_regex = re.compile(
            r'^detail (?:[^\s]+ [^\s]+ [^\s]+ )?verdict ([^\s]+)$',
            flags=re.I)
        statuses = {
            0: 'failed',
            1: 'passed',
            2: 'warning',
            3: 'good-not-tested',
            4: 'not-tested',
            5: 'info',
        }
        tests = {}
        for probeset in (webprobes, mailprobes):
            for probe in probeset:
                category = probe.category()
                for subtest in category.subtests.values():
                    testname = testname_regex.fullmatch(subtest.label).group(1)
                    tests[testname] = []
                    result_methods = [
                        method[1]
                        for method in inspect.getmembers(
                            subtest, predicate=inspect.ismethod)
                        if method[0].startswith('result_')
                    ]
                    for method in result_methods:
                        subtest.__init__()
                        arg_len = len(inspect.signature(method).parameters)
                        if arg_len:
                            method({None for i in range(arg_len)})
                        else:
                            method()
                        fullverdict = verdict_regex.fullmatch(subtest.verdict).group(0)
                        if fullverdict == "detail verdict not-tested":
                            continue
                        verdict = verdict_regex.fullmatch(subtest.verdict).group(1)
                        status = statuses[subtest.status]
                        tests[testname].append((verdict, status))
        self.tests = tests

    def setup(self):
        self.view_id = '2020_FS'
        self._gather_tests_verdicts_categories()
        self.settings = {
            BatchRequestType.web: {
                'ipv6': {
                    'ns_aaaa': {'api_field': 'web_ipv6_ns_address', 'translation_part': 'ns-AAAA'},
                    'ns_reach': {'api_field': 'web_ipv6_ns_reach', 'translation_part': 'ns-reach'},
                    'web_aaaa': {'api_field': 'web_ipv6_ws_address', 'translation_part': 'web-AAAA'},
                    'web_reach': {'api_field': 'web_ipv6_ws_reach', 'translation_part': 'web-reach'},
                    'web_ipv46': {'api_field': 'web_ipv6_ws_similar', 'translation_part': 'web-ipv46'},
                },
                'dnssec': {
                    'dnssec_exists': {'api_field': 'web_dnssec_exist', 'translation_part': 'exists'},
                    'dnssec_valid': {'api_field': 'web_dnssec_valid', 'translation_part': 'valid'},
                },
                'tls': {
                    'https_exists': {'api_field': 'web_https_http_available', 'translation_part': 'https-exists'},
                    'https_forced': {'api_field': 'web_https_http_redirect', 'translation_part': 'https-forced'},
                    'https_hsts': {'api_field': 'web_https_http_hsts', 'translation_part': 'http-compression'},
                    'http_compression': {'api_field': 'web_https_http_compress', 'translation_part': 'https-hsts'},
                    'tls_version': {'api_field': 'web_https_tls_version', 'translation_part': 'version'},
                    'tls_ciphers': {'api_field': 'web_https_tls_ciphers', 'translation_part': 'ciphers'},
                    'tls_cipher_order': {'api_field': 'web_https_tls_cipher_order',
                                         'translation_part': 'ciphers-order'},
                    'fs_params': {'api_field': 'web_https_tls_keyexchange', 'translation_part': 'fs-params'},
                    'kex_hash_func': {'api_field': 'web_https_tls_keyexchange_hash_function',
                                      'translation_part': 'kex-hash-func'},
                    'tls_compression': {'api_field': 'web_https_tls_compress', 'translation_part': 'compression'},
                    'renegotiation_secure': {'api_field': 'web_https_tls_secreneg',
                                             'translation_part': 'renegotiation-secure'},
                    'renegotiation_client': {'api_field': 'web_https_tls_clientreneg',
                                             'translation_part': 'renegotiation-client'},
                    'zero_rtt': {'api_field': 'web_https_tls_zero_rtt', 'translation_part': 'zero-rtt'},
                    'ocsp_stapling': {'api_field': 'web_https_tls_ocsp_stapling', 'translation_part': 'ocsp-stapling'},
                    'cert_trust': {'api_field': 'web_https_cert_chain', 'translation_part': 'cert-trust'},

                    'cert_pubkey': {'api_field': 'web_https_cert_pubkey', 'translation_part': 'cert-pubkey'},
                    'cert_signature': {'api_field': 'web_https_cert_sig', 'translation_part': 'cert-signature'},
                    'cert_hostmatch': {'api_field': 'web_https_cert_domain', 'translation_part': 'cert-hostmatch'},
                    'dane_exists': {'api_field': 'web_https_dane_exist', 'translation_part': 'dane-exists'},
                    'dane_valid': {'api_field': 'web_https_dane_valid', 'translation_part': 'dane-valid'},
                },
                'appsecpriv': {
                    'http_x_frame': {'api_field': 'web_appsecpriv_x_frame_options', 'translation_part': 'http-x-frame'},
                    'http_x_content_type': {'api_field': 'web_appsecpriv_x_content_type_options',
                                            'translation_part': 'http-x-content-type'},
                    'http_x_xss': {'api_field': 'web_appsecpriv_x_xss_protection', 'translation_part': 'http-x-xss'},
                    'http_csp': {'api_field': 'web_appsecpriv_csp', 'translation_part': 'http-csp'},
                    'http_referrer_policy': {'api_field': 'web_appsecpriv_referrer_policy',
                                             'translation_part': 'http-referrer-policy'},
                },
            },
            BatchRequestType.mail: {
                'ipv6': {
                    'ns_aaaa': {'api_field': 'mail_ipv6_ns_address', 'translation_part': ''},
                    'ns_reach': {'api_field': 'mail_ipv6_ns_reach', 'translation_part': ''},
                    'mx_aaaa': {'api_field': 'mail_ipv6_mx_address', 'translation_part': ''},
                    'mx_reach': {'api_field': 'mail_ipv6_mx_reach', 'translation_part': ''},
                },
                'dnssec': {
                    'dnssec_exists': {'api_field': 'mail_dnssec_mailto_exist', 'translation_part': ''},
                    'dnssec_valid': {'api_field': 'mail_dnssec_mailto_valid', 'translation_part': ''},
                    'dnssec_mx_exists': {'api_field': 'mail_dnssec_mx_exist', 'translation_part': ''},
                    'dnssec_mx_valid': {'api_field': 'mail_dnssec_mx_valid', 'translation_part': ''},
                },
                'auth': {
                    'dkim': {'api_field': 'mail_auth_dkim_exist', 'translation_part': ''},
                    'dmarc': {'api_field': 'mail_auth_dmarc_exist', 'translation_part': ''},
                    'dmarc_policy': {'api_field': 'mail_auth_dmarc_policy', 'translation_part': ''},
                    'spf': {'api_field': 'mail_auth_spf_exist', 'translation_part': ''},
                    'spf_policy': {'api_field': 'mail_auth_spf_policy', 'translation_part': ''},
                },
                'tls': {
                    'starttls_exists': {'api_field': 'mail_starttls_tls_available', 'translation_part': ''},
                    'tls_version': {'api_field': 'mail_starttls_tls_version', 'translation_part': ''},
                    'tls_ciphers': {'api_field': 'mail_starttls_tls_ciphers', 'translation_part': ''},
                    'fs_params': {'api_field': 'mail_starttls_tls_keyexchange', 'translation_part': ''},
                    'tls_compression': {'api_field': 'mail_starttls_tls_compress', 'translation_part': ''},
                    'renegotiation_secure': {'api_field': 'mail_starttls_tls_secreneg', 'translation_part': ''},
                    'renegotiation_client': {'api_field': 'mail_starttls_tls_clientreneg', 'translation_part': ''},
                    'cert_trust': {'api_field': 'mail_starttls_cert_chain', 'translation_part': ''},
                    'cert_pubkey': {'api_field': 'mail_starttls_cert_pubkey', 'translation_part': ''},
                    'cert_signature': {'api_field': 'mail_starttls_cert_sig', 'translation_part': ''},
                    'cert_hostmatch': {'api_field': 'mail_starttls_cert_domain', 'translation_part': ''},
                    'dane_exists': {'api_field': 'mail_starttls_dane_exist', 'translation_part': ''},
                    'dane_valid': {'api_field': 'mail_starttls_dane_valid', 'translation_part': ''},
                    'dane_rollover': {'api_field': 'mail_starttls_dane_rollover', 'translation_part': ''},
                },
            },
        }

    def get_view_data(self, batch_request_type, batch_domain):
        verdict_regex = re.compile(r'.*verdict ([^\s]+)$', flags=re.I)
        statuses = {
            0: 'failed',
            1: 'passed',
            2: 'warning',
            3: 'good-not-tested',
            4: 'not-tested',
            5: 'info',
        }
        view_data = []
        batch_test = batch_domain.get_batch_test()
        for report_model, name_map in self.settings[batch_request_type].items():
            report = getattr(batch_test.report, report_model).report
            for subtest, data in report.items():
                if name_map.get(subtest):
                    if (report_model == 'ipv6'
                            and subtest in ('ns_aaaa, ns_reach')):
                        test_type = 'web-mail'
                    else:
                        test_type = f'{batch_request_type}'.lower()
                    verdict = verdict_regex.fullmatch(data['verdict']).group(1)
                    status = statuses[data['status']]
                    view_data.append(dict(
                        name=f'{name_map[subtest]["api_field"]}',
                        verdict=f'{verdict}',
                        status=f'{status}',
                        translation_key=f'{test_type}_{report_model}_{name_map[subtest]["translation_part"]}',
                    ))

        #if batch_request_type == BatchRequestType.mail:
        #    self._get_dmarc_extra_info(batch_domain, view_data)
        #    self._get_starttls_extra_info(batch_domain, view_data)
        return view_data


def _create_views_map(view_instances):
    views_map = dict()
    for view in view_instances:
        name = _camel_case_to_snake(view.__class__.__name__)
        views_map[name] = view
    return views_map


VIEWS_MAP = _create_views_map([
    TlsAvailableView(),
    TlsNcscWebView(),
    DmarcView(),
    DkimView(),
    SpfView(),
    Ipv6NameserverView(),
    Ipv6WebserverView(),
    Ipv6MailserverView(),
    DnssecEmailDomainView(),
    DnssecMailserverDomainView(),
    DaneView(),
    HttpsEnforcedView(),
    HstsView(),
    RawReportsView(),
    ForumStandaardisatieView(),
    ForumStandaardisatieNewView(),
])
