# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from collections import namedtuple, defaultdict
import http.client
import re
import socket

from .tls_connection import NoIpError, http_fetch, MAX_REDIRECT_DEPTH
from .tls_connection import ConnectionSocketException
from .tls_connection import ConnectionHandshakeException
from .. import scoring


def get_multiple_values_from_header(header):
    """
    Get all the values for the header.

    Multiple values of the same header are in a comma separated list; make sure
    to ignore white space when splitting the values.

    """
    return [value.strip() for value in header.split(',')]


class HeaderCheckerContentEncoding(object):
    """
    Class for checking the Content-Encoding HTTP header.

    """
    def __init__(self):
        self.name = "Content-Encoding"

    def check(self, value, results, domain):
        """
        Check if the header has any value.

        """
        if value:
            results['http_compression_enabled'] = True
            score = scoring.WEB_TLS_HTTP_COMPRESSION_BAD
            results['http_compression_score'] = score

    def get_positive_values(self):
        return {
            'http_compression_enabled': False,
            'http_compression_score': scoring.WEB_TLS_HTTP_COMPRESSION_GOOD,
        }

    def get_negative_values(self):
        return {
            'http_compression_enabled': True,
            'http_compression_score': scoring.WEB_TLS_HTTP_COMPRESSION_BAD,
        }


class HeaderCheckerContentSecurityPolicy(object):
    """
    Class for checking the Content-Security-Policy HTTP header.

    """
    class ParseResult():
        def __init__(self):
            self.has_unsafe_inline = False
            self.has_unsafe_eval = False
            self.has_unsafe_hashes = False
            self.has_http = False
            self.has_data = False
            self.has_default_src = False
            self.has_frame_src = False
            self.has_frame_ancestors = False
            self.has_invalid_host = False

        def failed(self):
            if (self.has_unsafe_inline or self.has_unsafe_eval or self.has_http
                    or self.has_data or self.has_invalid_host
                    or self.has_unsafe_hashes
                    or not (self.has_default_src and self.has_frame_src
                            and self.has_frame_ancestors)):
                return True
            return False

        def __str__(self):
            """
            Could be used together with tests/unittests/test_tasks_http_headers.py
            for debugging.
            """
            return (
                f"has_unsafe_inline: {self.has_unsafe_inline}\n"
                f"has_unsafe_eval: {self.has_unsafe_eval}\n"
                f"has_unsafe_hashes: {self.has_unsafe_hashes}\n"
                f"has_http: {self.has_http}\n"
                f"has_data: {self.has_data}\n"
                f"has_default_src: {self.has_default_src}\n"
                f"has_frame_src: {self.has_frame_src}\n"
                f"has_frame_ancestors: {self.has_frame_ancestors}\n"
                f"has_invalid_host: {self.has_invalid_host}\n")

    Directive = namedtuple('Directive', [
        'default', 'values', 'values_optional', 'values_regex_all'],
        defaults=[[], [], False, False])
    host_source_regex = re.compile(
        r"^(?:(?P<scheme>.+)://)?"
        r"(?P<host>[^:/']+|\[.+\])"
        r"(?::(?P<port>\d+|\*))?"
        r"(?P<path>\/.*)?$")
    scheme_source_regex = re.compile(
        r'^(?P<scheme>https?|data|mediastream|blob|filesystem):$')
    self_none_regex = re.compile(r"^(?:(?P<self>'self')|(?P<none>'none'))$")
    other_source_regex = re.compile(
        r"(?:"
        r"(?P<self>'self')|(?P<unsafe_eval>'unsafe-eval')"
        r"|(?P<unsafe_hashes>'unsafe-hashes')"
        r"|(?P<unsafe_inline>'unsafe-inline')|(?P<none>'none')"
        r"|'nonce-[+a-zA-Z0-9/]+=*'"
        r"|'(?:sha256|sha384|sha512)-[+a-zA-Z0-9/]+=*')")
    strict_dynamic_regex = re.compile(r"'strict-dynamic'")
    report_sample_regex = re.compile(r"(?P<report_sample>'report-sample')")
    plugin_types_regex = re.compile(r'[^/]+/[^/]+')
    sandox_values_regex = re.compile(
        r'(?:allow-downloads-without-user-activation|allow-forms|allow-modals'
        r'|allow-orientation-lock|allow-pointer-lock|allow-popups'
        r'|allow-popups-to-escape-sandbox|allow-presentation|allow-same-origin'
        r'|allow-scripts|allow-storage-access-by-user-activation'
        r'|allow-top-navigation|allow-top-navigation-by-user-activation)')
    directives = {
        'child-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'connect-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'default-src': Directive(
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'font-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'frame-src': Directive(
            default=['child-src', 'default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'img-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'manifest-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'media-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'object-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'prefetch-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'script-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'script-src-elem': Directive(
            default=['script-src', 'default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'script-src-attr': Directive(
            default=['script-src', 'default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'style-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'style-src-elem': Directive(
            default=['style-src', 'default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                report_sample_regex],
        ),
        'style-src-attr': Directive(
            default=['style-src', 'default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                report_sample_regex],
        ),
        'worker-src': Directive(
            default=['child-src', 'script-src', 'default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'base-uri': Directive(
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'plugin-types': Directive(
            values=[plugin_types_regex],
        ),
        'sandbox': Directive(
            values=[sandox_values_regex],
            values_optional=True,
        ),
        'form-action': Directive(
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'frame-ancestors': Directive(
            values=[host_source_regex, scheme_source_regex, self_none_regex],
        ),
        'navigate-to': Directive(
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'report-to': Directive(
            # It could be anything in the Report-To header.
            values=[re.compile(r'.+')],
        ),
        'block-all-mixed-content': Directive(
        ),
        'trusted-types': Directive(
            values=[re.compile(
                r"^(?:'none'|"
                r"(?:\*|[\w\-#=\/@.%]+)"
                r"(?:(?: (?:\*|[\w\-#=\/@.%]+))+"
                r"(?: 'allow-duplicates')?)?)$")],
            values_optional=True,
            values_regex_all=True,
        ),
        'upgrade-insecure-requests': Directive(),
    }

    def __init__(self):
        self.name = "Content-Security-Policy"
        self.parsed = None
        self.result = None

    def _get_directives(self, directives):
        if not directives:
            return self.parsed.keys()
        res = []
        for directive in directives:
            if directive in self.parsed:
                res.append(directive)
            else:
                for default in self.directives[directive].default:
                    if default in self.parsed:
                        res.append(default)
                        break
        return res

    def _check_matched_for_groups(self, groups, directives=None):
        """
        Check the matched content for any appearance specified in groups,
        on the specified directives (or any if not specified).

        """
        dirs = self._get_directives(directives)
        for dir in dirs:
            for group, values in groups.items():
                for match in self.parsed[dir]:
                    if group in match.groupdict() and match.group(group):
                        if not values:
                            return True
                        for value in values:
                            if value == match.group(group):
                                return True
        return False

    def _check_default_src(self, domain):
        directive = 'default-src'
        domain = domain.rstrip('.')
        expected_sources = 0
        matched_host = 0
        found_self = False
        found_hosts = set()
        for match in self.parsed[directive]:
            if 'none' in match.groupdict() and match.group('none'):
                # There is 'none' we don't care about the rest.
                return True
            elif 'self' in match.groupdict() and match.group('self'):
                expected_sources += 1
                found_self = True
            elif 'report_sample' in match.groupdict() and match.group('report_sample'):
                expected_sources += 1
            elif ('scheme' in match.groupdict() and match.group('scheme')
                  and match.string == "https:"):
                expected_sources += 1
            elif 'host' in match.groupdict() and match.group('host'):
                expected_sources += 1
                host = match.group('host').rstrip('.')
                found_hosts.add(host)
                if domain == host:
                    matched_host += 1
                elif host.startswith('*.'):
                    host = host.split('*.', 1)
                    if not host[1]:
                        return False
                    if not domain.endswith(host[1]):
                        return False
                    matched_host += 1
        if not found_self:
            return False
        # Check that at least one host matched and that the hosts have the same
        # base domain.
        if found_hosts:
            if not matched_host:
                return False
            base_domain = min(found_hosts, key=len)
            for host in found_hosts:
                if not host.endswith(base_domain):
                    return False
        # Check that all the values are the expected ones.
        if expected_sources == len(self.parsed[directive]):
            return True
        return False

    def _verdict(self, domain):
        self.result.has_http = self._check_matched_for_groups(
            dict(scheme=['http', '*']))
        self.result.has_data = self._check_matched_for_groups(
            dict(scheme=['data', '*']),
            directives=['object-src', 'script-src'])
        self.result.has_invalid_host = self._check_matched_for_groups(
            dict(host=['*', '127.0.0.1']))
        self.result.has_unsafe_inline = self._check_matched_for_groups(
            dict(unsafe_inline=[]))
        self.result.has_unsafe_eval = self._check_matched_for_groups(
            dict(unsafe_eval=[]))
        self.result.has_unsafe_hashes = self._check_matched_for_groups(
            dict(unsafe_hashes=[]))
        self.result.has_default_src = self._check_default_src(domain)
        self.result.has_frame_src = self._check_matched_for_groups(
            dict(self=[], none=[]),
            directives=['frame-src'])
        self.result.has_frame_ancestors = self._check_matched_for_groups(
            dict(self=[], none=[]),
            directives=['frame-ancestors'])

    def check(self, value, results, domain):
        """
        Check if the header respects the following:
            - No `unsafe-inline`;
            - No `unsafe-eval`;
            - No `unsafe-hashes`;
            - `default-src` needs to be defined and include `'self'` or
              `'none'`.  It can also include a host source relative to the
              domain (to allow subdomain definitions) and `'report_sample'`;
            - `frame-src` and `frame-ancestors` need to defined
              and include `'self'` or `'none'`;
            - No wildcard or '127.0.0.1' for host;
            - `http:` should not be used as a scheme;
            - `data:` should not be used as a scheme for `object-src`,
              `script-src` (`default-src` cannot contain `data:` from
              the restrains above).

        """
        if not value:
            results['content_security_policy_enabled'] = False
            score = scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_BAD
            results['content_security_policy_score'] = score
        else:
            values = get_multiple_values_from_header(value)
            results['content_security_policy_values'].extend(values)

            self.parsed = defaultdict(list)
            self.result = self.ParseResult()

            for header in values:
                dirs = filter(None, header.split(';'))
                for content in dirs:
                    content = content.strip().split()
                    dir = content[0]
                    values = content[1:]
                    # Only care for known directives.
                    if dir in self.directives:
                        if not values:
                            if (not self.directives[dir].values
                                    or self.directives[dir].values_optional):
                                # No-values allowed; keep.
                                self.parsed[dir]
                            continue

                        if self.directives[dir].values_regex_all:
                            test_values = [' '.join(values)]
                        else:
                            test_values = values

                        # Check the directives.
                        for value in test_values:
                            for value_regex in self.directives[dir].values:
                                match = value_regex.match(value)
                                if match:
                                    self.parsed[dir].append(match)
                                    break

            self._verdict(domain)
            if self.result.failed():
                results['content_security_policy_enabled'] = False
                score = scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_BAD
                results['content_security_policy_score'] = score

    def get_positive_values(self):
        score = scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_GOOD
        return {
            'content_security_policy_enabled': True,
            'content_security_policy_score': score,
            'content_security_policy_values': [],
        }

    def get_negative_values(self):
        score = scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_BAD
        return {
            'content_security_policy_enabled': False,
            'content_security_policy_score': score,
            'content_security_policy_values': [],
        }


class HeaderCheckerStrictTransportSecurity(object):
    """
    Class for checking the Strict-Transport-Security HTTP header.

    """
    def __init__(self):
        self.name = "Strict-Transport-Security"
        self.first_time_seen = True
        self.min_allowed = 31536000  # 1 year

    def check(self, value, results, domain):
        """
        Check if the *first* HSTS header value is more than 6 months.

        """
        if self.first_time_seen and not value:
            results['hsts_enabled'] = False
            results['hsts_score'] = scoring.WEB_TLS_HSTS_BAD
            self.first_time_seen = False
        elif value:
            header_values = get_multiple_values_from_header(value)
            try:
                max_age = header_values[0].lower().split(
                    'max-age=')[1].split(';')[0]
                if self.first_time_seen and int(max_age) < self.min_allowed:
                    results['hsts_score'] = scoring.WEB_TLS_HSTS_PARTIAL
                    self.first_time_seen = False
            except (ValueError, IndexError):
                if self.first_time_seen:
                    results['hsts_score'] = scoring.WEB_TLS_HSTS_BAD
                    results['hsts_enabled'] = False
                    self.first_time_seen = False
            results['hsts_policies'].extend(header_values)

    def get_positive_values(self):
        return {
            'hsts_enabled': True,
            'hsts_policies': [],
            'hsts_score': scoring.WEB_TLS_HSTS_GOOD,
        }

    def get_negative_values(self):
        return {
            'hsts_enabled': False,
            'hsts_policies': [],
            'hsts_score': scoring.WEB_TLS_HSTS_BAD,
        }


class HeaderCheckerXFrameOptions(object):
    """
    Class for checking the X-Frame-Options HTTP header.

    """
    def __init__(self):
        self.name = "X-Frame-Options"

    def check(self, value, results, domain):
        """
        Check if the header has any of the allowed values.

        """
        if not value:
            score = scoring.WEB_APPSECPRIV_X_FRAME_OPTIONS_BAD
            results['x_frame_options_score'] = score
            results['x_frame_options_enabled'] = False
        else:
            values = get_multiple_values_from_header(value)
            first_header = values[0].upper()
            if first_header not in ("DENY", "SAMEORIGIN"):
                score = scoring.WEB_APPSECPRIV_X_FRAME_OPTIONS_BAD
                results['x_frame_options_score'] = score
                results['x_frame_options_enabled'] = False
            results['x_frame_options_values'].extend(values)

    def get_positive_values(self):
        score = scoring.WEB_APPSECPRIV_X_FRAME_OPTIONS_GOOD
        return {
            'x_frame_options_enabled': True,
            'x_frame_options_score': score,
            'x_frame_options_values': [],
        }

    def get_negative_values(self):
        score = scoring.WEB_APPSECPRIV_X_FRAME_OPTIONS_BAD
        return {
            'x_frame_options_enabled': False,
            'x_frame_options_score': score,
            'x_frame_options_values': [],
        }


class HeaderCheckerXContentTypeOptions(object):
    """
    Class for checking the X-Content-Type-Options HTTP header.

    """
    def __init__(self):
        self.name = "X-Content-Type-Options"

    def check(self, value, results, domain):
        """
        Check if the header has the allowed value.

        """
        if not value:
            score = scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_BAD
            results['x_content_type_options_score'] = score
            results['x_content_type_options_enabled'] = False
        else:
            values = get_multiple_values_from_header(value)
            if not values[0].lower() == "nosniff":
                score = scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_BAD
                results['x_content_type_options_score'] = score
                results['x_content_type_options_enabled'] = False
            results['x_content_type_options_values'].extend(values)

    def get_positive_values(self):
        score = scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_GOOD
        return {
            'x_content_type_options_enabled': True,
            'x_content_type_options_score': score,
            'x_content_type_options_values': [],
        }

    def get_negative_values(self):
        score = scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_BAD
        return {
            'x_content_type_options_enabled': False,
            'x_content_type_options_score': score,
            'x_content_type_options_values': [],
        }


class HeaderCheckerXXssProtection(object):
    """
    Class for checking the X-Xss-Protection HTTP header.

    """
    def __init__(self):
        self.name = "X-Xss-Protection"

    def check(self, value, results, domain):
        """
        Check if XSS protection is enabled.

        """
        if not value:
            score = scoring.WEB_APPSECPRIV_X_XSS_PROTECTION_BAD
            results['x_xss_protection_score'] = score
            results['x_xss_protection_enabled'] = False
        else:
            values = get_multiple_values_from_header(value)
            enabled = values[0].split(";")[0]
            if enabled == "0":
                score = scoring.WEB_APPSECPRIV_X_XSS_PROTECTION_BAD
                results['x_xss_protection_score'] = score
                results['x_xss_protection_enabled'] = False
            results['x_xss_protection_values'].extend(values)

    def get_positive_values(self):
        score = scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_GOOD
        return {
            'x_xss_protection_enabled': True,
            'x_xss_protection_score': score,
            'x_xss_protection_values': [],
        }

    def get_negative_values(self):
        score = scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_BAD
        return {
            'x_xss_protection_enabled': False,
            'x_xss_protection_score': score,
            'x_xss_protection_values': [],
        }


class HeaderCheckerReferrerPolicy(object):
    """
    Class for checking the Referrer-Policy HTTP header.

    """
    def __init__(self):
        self.name = "Referrer-Policy"

    def check(self, value, results, domain):
        """
        Check if the header has any of the allowed values.

        """
        if value == "":
            # Empty string defaults to 'no-referrer-when-downgrade'.
            results['referrer_policy_values'] = ['""']

        elif not value:
            score = scoring.WEB_APPSECPRIV_REFERRER_POLICY_BAD
            results['referrer_policy_score'] = score
            results['referrer_policy_enabled'] = False

        else:
            values = get_multiple_values_from_header(value)
            for value in values:
                if value.lower() not in [
                        'no-referrer',
                        'no-referrer-when-downgrade',
                        'origin',
                        'origin-when-cross-origin',
                        'same-origin',
                        'strict-origin',
                        'strict-origin-when-cross-origin',
                        'unsafe-url',
                        ]:
                    score = scoring.WEB_APPSECPRIV_REFERRER_POLICY_BAD
                    results['referrer_policy_score'] = score
                    results['referrer_policy_enabled'] = False
                else:
                # has one of the above values, which is good. let's check more strict values
                    if value.lower() not in [
                            'no-referrer',
                            'same-origin',
                            ]:
                        score = scoring.WEB_APPSECPRIV_REFERRER_POLICY_INFO
                        results['referrer_policy_score'] = score
                        results['referrer_policy_enabled'] = True
            results['referrer_policy_values'].extend(values)

    def get_positive_values(self):
        score = scoring.WEB_APPSECPRIV_REFERRER_POLICY_GOOD
        return {
            'referrer_policy_enabled': True,
            'referrer_policy_score': score,
            'referrer_policy_values': [],
        }

    def get_negative_values(self):
        score = scoring.WEB_APPSECPRIV_REFERRER_POLICY_BAD
        return {
            'referrer_policy_enabled': False,
            'referrer_policy_score': score,
            'referrer_policy_values': [],
        }


def http_headers_check(af_ip_pair, domain, header_checkers, task):
    results = dict()
    # set defaults to positive values. Header tests return negative values if
    # a test failed.
    for h in header_checkers:
        results.update(h.get_positive_values())

    put_headers = (("Accept-Encoding", "compress, deflate, exi, gzip, "
                                       "pack200-gzip, x-compress, x-gzip"),)
    get_headers = [h.name for h in header_checkers]
    try:
        conn, res, headers, visited_hosts = http_fetch(
            domain, af=af_ip_pair[0], path="", port=443, task=task,
            ip_address=af_ip_pair[1], put_headers=put_headers,
            depth=MAX_REDIRECT_DEPTH,
            needed_headers=get_headers)
    except (socket.error, http.client.BadStatusLine, NoIpError,
            ConnectionHandshakeException, ConnectionSocketException):
        # Not able to connect, return negative values
        for h in header_checkers:
            results.update(h.get_negative_values())
        results['server_reachable'] = False
    else:
        if 443 in headers:
            for name, value in headers[443]:
                for header_checker in header_checkers:
                    if name == header_checker.name:
                        header_checker.check(value, results, domain)
                        break

    return results
