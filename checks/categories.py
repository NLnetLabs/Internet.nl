# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from . import scoring
from .scoring import STATUS_FAIL, STATUS_NOT_TESTED
from .scoring import STATUS_NOTICE, STATUS_INFO, STATUS_ERROR
from .scoring import STATUS_SUCCESS, ORDERED_STATUSES


# --- Base classes
#
class Category(object):
    def __init__(self, name, subtests):
        self.name = name
        self.subtests = {}
        for subtest in subtests:
            inited = subtest()
            self.subtests[inited.name] = inited
        self.score_fields, self.max_score = self._check_mandatory_subtests()

    def gen_report(self):
        """
        Fill the report with the state of all subtests.

        """
        report = {}
        for name, subtest in self.subtests.items():
            report[name] = subtest.fill_report()
        return report

    def update_from_report(self, report):
        """
        Update the subtests with values from the report.

        """
        for name, result in report.items():
            for field, value in result.items():
                setattr(self.subtests[name], field, value)
        self.score_fields, self.max_score = self._check_mandatory_subtests()

    def _check_mandatory_subtests(self):
        """
        Return the score fields and the possible max score for this category
        based on the mandatory tests.

        """
        max_score = 0
        score_fields = []
        for name, subtest in self.subtests.items():
            if (subtest.worst_status == scoring.STATUS_FAIL
                    and subtest.model_score_field):
                score_fields.append(subtest.model_score_field)
                if subtest.full_score:
                    max_score += subtest.full_score
        return score_fields, max_score


class Subtest(object):
    def __init__(
            self, name="", label="", explanation="", tech_string="",
            model_score_field=None,
            full_score=None,
            worst_status=STATUS_FAIL,
            init_status=STATUS_NOT_TESTED,
            init_verdict="detail verdict not-tested",
            init_tech_type="table",
            init_tech_data="detail tech data not-tested"):
        self.name = name
        self.label = label
        self.explanation = explanation
        self.tech_string = tech_string
        self.model_score_field = model_score_field
        self.full_score = full_score
        self.worst_status = worst_status
        self.status = init_status
        self.verdict = init_verdict
        self.tech_type = init_tech_type
        self.tech_data = init_tech_data

    def _status(self, status, override=False):
        """
        Make sure that the status assigned while testing does not overcome the
        _WORST_STATUS configured for this subtest.

        """
        if override:
            self.status = status
            return

        if ORDERED_STATUSES[status] >= ORDERED_STATUSES[self.worst_status]:
            self.status = status
        else:
            self.status = self.worst_status

    def fill_report(self):
        """
        Return the final state for this subtest.

        """
        return {
            'label': self.label,
            'status': self.status,
            'worst_status': self.worst_status,
            'verdict': self.verdict,
            'exp': self.explanation,
            'tech_type': self.tech_type,
            'tech_string': self.tech_string,
            'tech_data': self.tech_data,
        }


# --- Categories
#
class WebIpv6(Category):
    def __init__(self, name="web-ipv6"):
        subtests = [
            Ipv6NsAaaa,
            Ipv6NsReach,
            WebIpv6WsAaaa,
            WebIpv6WsReach,
            WebIpv6WsIpv46,
        ]
        super(WebIpv6, self).__init__(name, subtests)


class WebDnssec(Category):
    def __init__(self, name="web-dnssec"):
        subtests = [
            WebDnssecExists,
            WebDnssecValid,
        ]
        super(WebDnssec, self).__init__(name, subtests)


class WebTls(Category):
    def __init__(self, name="web-tls"):
        subtests = [
            WebTlsHttpsExists,
            WebTlsHttpsForced,
            WebTlsHttpsHsts,
            WebTlsHttpCompression,
            WebTlsFsParams,
            WebTlsCiphers,
            WebTlsCipherOrder,
            WebTlsVersion,
            WebTlsCompression,
            WebTlsRenegotiationSecure,
            WebTlsRenegotiationClient,
            WebTlsCertTrust,
            WebTlsCertPubkey,
            WebTlsCertSignature,
            WebTlsCertHostmatch,
            WebTlsDaneExists,
            WebTlsDaneValid,
            WebTlsZeroRTT,
            WebTlsOCSPStapling,
            WebTlsKexHashFunc,
            # WebTlsDaneRollover,
        ]
        super(WebTls, self).__init__(name, subtests)


class WebAppsecpriv(Category):
    def __init__(self, name="web-appsecpriv"):
        subtests = [
            WebAppsecprivHttpXFrame,
            WebAppsecprivHttpReferrerPolicy,
            WebAppsecprivHttpCsp,
            WebAppsecprivHttpXContentType,
            # TODO: To be removed in the future.
            #WebAppsecprivHttpXXss,
        ]
        super(WebAppsecpriv, self).__init__(name, subtests)


class MailIpv6(Category):
    def __init__(self, name="mail-ipv6"):
        subtests = [
            Ipv6NsAaaa,
            Ipv6NsReach,
            MailIpv6MxAaaa,
            MailIpv6MxReach,
        ]
        super(MailIpv6, self).__init__(name, subtests)


class MailDnssec(Category):
    def __init__(self, name="mail-dnssec"):
        subtests = [
            MailDnssecExists,
            MailDnssecValid,
            MailDnssecMxExists,
            MailDnssecMxValid,
        ]
        super(MailDnssec, self).__init__(name, subtests)


class MailAuth(Category):
    def __init__(self, name="mail-auth"):
        subtests = [
            MailAuthDmarc,
            MailAuthDmarcPolicy,
            MailAuthDkim,
            MailAuthSpf,
            MailAuthSpfPolicy,
        ]
        super(MailAuth, self).__init__(name, subtests)


class MailTls(Category):
    def __init__(self, name="mail-tls"):
        subtests = [
            MailTlsStarttlsExists,
            MailTlsFsParams,
            MailTlsCiphers,
            MailTlsCipherOrder,
            MailTlsVersion,
            MailTlsCompression,
            MailTlsRenegotiationSecure,
            MailTlsRenegotiationClient,
            MailTlsCertTrust,
            MailTlsCertPubkey,
            MailTlsCertSignature,
            MailTlsCertHostmatch,
            MailTlsDaneExists,
            MailTlsDaneValid,
            MailTlsDaneRollover,
            MailTlsZeroRTT,
            MailTlsKexHashFunc,
            # MailTlsOCSPStapling,  # Disabled for mail.
        ]
        super(MailTls, self).__init__(name, subtests)


# --- Subtests
#
# --- IPV6
class Ipv6NsAaaa(Subtest):
    def __init__(self):
        super(Ipv6NsAaaa, self).__init__(
            name="ns_aaaa",
            label="detail web-mail ipv6 ns-AAAA label",
            explanation="detail web-mail ipv6 ns-AAAA exp",
            tech_string="detail web-mail ipv6 ns-AAAA tech table",
            worst_status=scoring.IPV6_NS_CONN_WORST_STATUS)

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web-mail ipv6 ns-AAAA verdict bad"
        self.tech_data = tech_data

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web-mail ipv6 ns-AAAA verdict good"
        self.tech_data = tech_data

    def result_only_one(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web-mail ipv6 ns-AAAA verdict other"
        self.tech_data = tech_data


class Ipv6NsReach(Subtest):
    def __init__(self):
        super(Ipv6NsReach, self).__init__(
            name="ns_reach",
            label="detail web-mail ipv6 ns-reach label",
            explanation="detail web-mail ipv6 ns-reach exp",
            tech_string="detail web-mail ipv6 ns-reach tech table",
            init_tech_type="",
            worst_status=scoring.IPV6_NS_CONN_WORST_STATUS,
            full_score=scoring.IPV6_NS_CONN_GOOD,
            model_score_field="ns_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web-mail ipv6 ns-reach verdict good"

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web-mail ipv6 ns-reach verdict bad"
        self.tech_data = tech_data
        self.tech_type = "table"


class WebIpv6WsAaaa(Subtest):
    def __init__(self):
        super(WebIpv6WsAaaa, self).__init__(
            name="web_aaaa",
            label="detail web ipv6 web-AAAA label",
            explanation="detail web ipv6 web-AAAA exp",
            tech_string="detail web ipv6 web-AAAA tech table",
            worst_status=scoring.WEB_IPV6_WS_CONN_WORST_STATUS)

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web ipv6 web-AAAA verdict bad"
        self.tech_data = tech_data

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web ipv6 web-AAAA verdict good"
        self.tech_data = tech_data


class WebIpv6WsReach(Subtest):
    def __init__(self):
        super(WebIpv6WsReach, self).__init__(
            name="web_reach",
            label="detail web ipv6 web-reach label",
            explanation="detail web ipv6 web-reach exp",
            tech_string="detail web ipv6 web-reach tech table",
            init_tech_type="",
            worst_status=scoring.WEB_IPV6_WS_CONN_WORST_STATUS,
            full_score=scoring.WEB_IPV6_WS_CONN_GOOD,
            model_score_field="web_score")

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web ipv6 web-reach verdict bad"
        self.tech_data = tech_data
        self.tech_type = "table"

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web ipv6 web-reach verdict good"


class WebIpv6WsIpv46(Subtest):
    def __init__(self):
        super(WebIpv6WsIpv46, self).__init__(
            name="web_ipv46",
            label="detail web ipv6 web-ipv46 label",
            explanation="detail web ipv6 web-ipv46 exp",
            init_tech_type="",
            worst_status=scoring.WEB_IPV6_WS_SIMHASH_WORST_STATUS,
            full_score=scoring.WEB_IPV6_WS_SIMHASH_OK,
            model_score_field="web_simhash_score")

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web ipv6 web-ipv46 verdict bad"

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web ipv6 web-ipv46 verdict good"

    def result_no_v4(self):
        self.worst_status = STATUS_NOT_TESTED


class MailIpv6MxAaaa(Subtest):
    def __init__(self):
        super(MailIpv6MxAaaa, self).__init__(
            name="mx_aaaa",
            label="detail mail ipv6 mx-AAAA label",
            explanation="detail mail ipv6 mx-AAAA exp",
            tech_string="detail mail ipv6 mx-AAAA tech table",
            worst_status=STATUS_NOTICE)

    def was_tested(self):
        self.worst_status = scoring.MAIL_IPV6_MX_CONN_WORST_STATUS

    def result_bad(self, tech_data):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail ipv6 mx-AAAA verdict bad"
        self.tech_data = tech_data

    def result_good(self, tech_data):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail ipv6 mx-AAAA verdict good"
        self.tech_data = tech_data

    def result_no_mailservers(self):
        self._status(STATUS_NOT_TESTED)
        self.verdict = "detail mail ipv6 mx-AAAA verdict other"
        self.tech_type = ""

    def result_null_mx(self):
        self._status(STATUS_NOT_TESTED)
        self.verdict = "detail mail ipv6 mx-AAAA verdict null-mx"
        self.tech_type = ""

    def result_no_null_mx(self):
        self._status(STATUS_INFO)
        self.verdict = "detail mail ipv6 mx-AAAA verdict no-null-mx"
        self.tech_type = ""

    def result_invalid_null_mx(self):
        self._status(STATUS_NOTICE)
        self.verdict = "detail mail ipv6 mx-AAAA verdict invalid-null-mx"
        self.tech_type = ""


class MailIpv6MxReach(Subtest):
    def __init__(self):
        super(MailIpv6MxReach, self).__init__(
            name="mx_reach",
            label="detail mail ipv6 mx-reach label",
            explanation="detail mail ipv6 mx-reach exp",
            tech_string="detail mail ipv6 mx-reach tech table",
            init_tech_type="",
            worst_status=STATUS_NOTICE,
            full_score=scoring.MAIL_IPV6_MX_CONN_GOOD,
            model_score_field="mx_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_IPV6_MX_CONN_WORST_STATUS

    def result_not_tested_bad(self):
        self.worst_status = scoring.MAIL_IPV6_MX_CONN_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail ipv6 mx-reach verdict good"

    def result_bad(self, tech_data):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail ipv6 mx-reach verdict bad"
        self.tech_data = tech_data
        self.tech_type = "table"


# --- DNSSEC
class WebDnssecExists(Subtest):
    def __init__(self):
        super(WebDnssecExists, self).__init__(
            name="dnssec_exists",
            label="detail web dnssec exists label",
            explanation="detail web dnssec exists exp",
            tech_string="detail web dnssec exists tech table",
            worst_status=scoring.WEB_DNSSEC_WORST_STATUS)

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web dnssec exists verdict good"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web dnssec exists verdict bad"
        self.tech_data = tech_data

    def result_servfail(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web dnssec exists verdict servfail"
        self.tech_data = tech_data

    def result_resolver_error(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web dnssec exists verdict resolver-error"
        self.tech_data = tech_data


class WebDnssecValid(Subtest):
    def __init__(self):
        super(WebDnssecValid, self).__init__(
            name="dnssec_valid",
            label="detail web dnssec valid label",
            explanation="detail web dnssec valid exp",
            tech_string="detail web dnssec valid tech table",
            worst_status=scoring.WEB_DNSSEC_WORST_STATUS,
            full_score=scoring.WEB_DNSSEC_SECURE,
            model_score_field="score")

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web dnssec valid verdict good"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web dnssec valid verdict bad"
        self.tech_data = tech_data

    def result_unsupported_ds_algo(self, tech_data):
        self._status(STATUS_NOTICE)
        self.verdict = "detail web dnssec valid verdict unsupported-ds-algo"
        self.tech_data = tech_data

    def result_insecure(self, tech_data):
        self.tech_data = tech_data

    def result_servfail(self, tech_data):
        self.tech_data = tech_data

    def result_resolver_error(self, tech_data):
        self.tech_data = tech_data


class MailDnssecExists(Subtest):
    def __init__(self):
        super(MailDnssecExists, self).__init__(
            name="dnssec_exists",
            label="detail mail dnssec exists label",
            explanation="detail mail dnssec exists exp",
            tech_string="detail mail dnssec exists tech table",
            worst_status=scoring.MAIL_DNSSEC_WORST_STATUS)

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail dnssec exists verdict good"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail dnssec exists verdict bad"
        self.tech_data = tech_data

    def result_servfail(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail dnssec exists verdict servfail"
        self.tech_data = tech_data

    def result_resolver_error(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail dnssec exists verdict resolver-error"
        self.tech_data = tech_data


class MailDnssecValid(Subtest):
    def __init__(self):
        super(MailDnssecValid, self).__init__(
            name="dnssec_valid",
            label="detail mail dnssec valid label",
            explanation="detail mail dnssec valid exp",
            tech_string="detail mail dnssec valid tech table",
            worst_status=scoring.MAIL_DNSSEC_WORST_STATUS,
            full_score=scoring.MAIL_DNSSEC_SECURE,
            model_score_field="score")

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail dnssec valid verdict good"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail dnssec valid verdict bad"
        self.tech_data = tech_data

    def result_unsupported_ds_algo(self, tech_data):
        self._status(STATUS_NOTICE)
        self.verdict = "detail mail dnssec valid verdict unsupported-ds-algo"
        self.tech_data = tech_data

    def result_insecure(self, tech_data):
        self.tech_data = tech_data

    def result_servfail(self, tech_data):
        self.tech_data = tech_data

    def result_resolver_error(self, tech_data):
        self.tech_data = tech_data


class MailDnssecMxExists(Subtest):
    def __init__(self):
        super(MailDnssecMxExists, self).__init__(
            name="dnssec_mx_exists",
            label="detail mail dnssec mx-exists label",
            explanation="detail mail dnssec mx-exists exp",
            tech_string="detail mail dnssec mx-exists tech table",
            worst_status=STATUS_NOTICE)

    def was_tested(self):
        self.worst_status = scoring.MAIL_DNSSEC_WORST_STATUS

    def result_no_mailservers(self):
        self._status(STATUS_NOT_TESTED)
        self.verdict = "detail mail dnssec mx-exists verdict no-mailservers"

    def result_null_mx(self):
        self._status(STATUS_NOT_TESTED)
        self.verdict = "detail mail dnssec mx-exists verdict null-mx"

    def result_no_null_mx(self):
        self._status(STATUS_INFO)
        self.verdict = "detail mail dnssec mx-exists verdict no-null-mx"

    def result_invalid_null_mx(self):
        self._status(STATUS_NOTICE)
        self.verdict = "detail mail dnssec mx-exists verdict invalid-null-mx"

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail dnssec mx-exists verdict good"
        self.tech_data = "detail tech data yes"

    def result_bad(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail dnssec mx-exists verdict bad"
        self.tech_data = "detail tech data no"

    def result_servfail(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail dnssec mx-exists verdict servfail"

    def result_resolver_error(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail dnssec mx-exists verdict resolver-error"


class MailDnssecMxValid(Subtest):
    def __init__(self):
        super(MailDnssecMxValid, self).__init__(
            name="dnssec_mx_valid",
            label="detail mail dnssec mx-valid label",
            explanation="detail mail dnssec mx-valid exp",
            tech_string="detail mail dnssec mx-valid tech table",
            worst_status=STATUS_NOTICE)

    def was_tested(self):
        self.worst_status = scoring.MAIL_DNSSEC_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail dnssec mx-valid verdict good"
        self.tech_data = "detail tech data secure"

    def result_bad(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail dnssec mx-valid verdict bad"
        self.tech_data = "detail tech data bogus"

    def result_unsupported_ds_algo(self):
        self.was_tested()
        self._status(STATUS_NOTICE)
        self.verdict = (
            "detail mail dnssec mx-valid verdict unsupported-ds-algo")
        self.tech_data = "detail tech data insecure"

    def result_insecure(self):
        self.was_tested()
        self.tech_data = "detail tech data insecure"


# --- TLS
class WebTlsHttpsExists(Subtest):
    def __init__(self):
        super(WebTlsHttpsExists, self).__init__(
            name="https_exists",
            label="detail web tls https-exists label",
            explanation="detail web tls https-exists exp",
            tech_string="detail web tls https-exists tech table",
            worst_status=scoring.WEB_TLS_HTTPS_EXISTS_WORST_STATUS)

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls https-exists verdict good"
        self.tech_data = "detail tech data yes"

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls https-exists verdict bad"
        self.tech_data = "detail tech data no"

    def result_unreachable(self):
        self._status(STATUS_ERROR, override=True)
        self.verdict = "detail web tls https-exists verdict other"
        self.tech_data = "detail tech data not-reachable"


class WebTlsHttpsForced(Subtest):
    def __init__(self):
        super(WebTlsHttpsForced, self).__init__(
            name="https_forced",
            label="detail web tls https-forced label",
            explanation="detail web tls https-forced exp",
            tech_string="detail web tls https-forced tech table",
            worst_status=scoring.WEB_TLS_FORCED_HTTPS_WORST_STATUS,
            full_score=scoring.WEB_TLS_FORCED_HTTPS_GOOD,
            model_score_field="forced_https_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls https-forced verdict good"
        self.tech_data = "detail tech data yes"

    def result_no_http(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls https-forced verdict other"
        self.tech_data = "detail tech data not-applicable"

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls https-forced verdict bad"
        self.tech_data = "detail tech data no"


class WebTlsHttpsHsts(Subtest):
    def __init__(self):
        super(WebTlsHttpsHsts, self).__init__(
            name="https_hsts",
            label="detail web tls https-hsts label",
            explanation="detail web tls https-hsts exp",
            tech_string="detail web tls https-hsts tech table",
            worst_status=scoring.WEB_TLS_HSTS_WORST_STATUS,
            full_score=scoring.WEB_TLS_HSTS_GOOD,
            model_score_field="hsts_score")

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls https-hsts verdict good"
        self.tech_data = tech_data

    def result_bad_max_age(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls https-hsts verdict other"
        self.tech_data = tech_data

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls https-hsts verdict bad"
        self.tech_data = ""


class WebTlsHttpCompression(Subtest):
    def __init__(self):
        super(WebTlsHttpCompression, self).__init__(
            name="http_compression",
            label="detail web tls http-compression label",
            explanation="detail web tls http-compression exp",
            tech_string="detail web tls http-compression tech table",
            worst_status=scoring.WEB_TLS_HTTP_COMPRESSION_WORST_STATUS,
            full_score=scoring.WEB_TLS_HTTP_COMPRESSION_GOOD,
            model_score_field="http_compression_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls http-compression verdict good"
        self.tech_data = "detail tech data no"

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls http-compression verdict bad"
        self.tech_data = "detail tech data yes"


class WebTlsFsParams(Subtest):
    def __init__(self):
        super(WebTlsFsParams, self).__init__(
            name="fs_params",
            label="detail web tls fs-params label",
            explanation="detail web tls fs-params exp",
            init_tech_type="table_multi_col",
            tech_string="detail web tls fs-params tech table",
            worst_status=scoring.WEB_TLS_FS_WORST_STATUS,
            full_score=scoring.WEB_TLS_FS_GOOD,
            model_score_field="fs_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls fs-params verdict good"
        self.tech_data = ""

    def result_phase_out(self, tech_data):
        self._status(STATUS_NOTICE)
        self.verdict = "detail web tls fs-params verdict phase-out"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls fs-params verdict bad"
        self.tech_data = tech_data

    def result_no_dh_params(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls fs-params verdict na"
        self.tech_data = ""


class WebTlsCiphers(Subtest):
    def __init__(self):
        super(WebTlsCiphers, self).__init__(
            name="tls_ciphers",
            label="detail web tls ciphers label",
            explanation="detail web tls ciphers exp",
            init_tech_type="table_multi_col",
            tech_string="detail web tls ciphers tech table",
            worst_status=scoring.WEB_TLS_SUITES_WORST_STATUS,
            full_score=scoring.WEB_TLS_SUITES_GOOD,
            model_score_field="ciphers_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls ciphers verdict good"
        self.tech_data = ""

    def result_phase_out(self, tech_data):
        self._status(STATUS_NOTICE)
        self.verdict = "detail web tls ciphers verdict phase-out"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls ciphers verdict bad"
        self.tech_data = tech_data


class WebTlsCipherOrder(Subtest):
    def __init__(self):
        super(WebTlsCipherOrder, self).__init__(
            name="tls_cipher_order",
            label="detail web tls cipher-order label",
            explanation="detail web tls cipher-order exp",
            init_tech_type="table_multi_col",
            tech_string="detail web tls cipher-order tech table",
            worst_status=scoring.WEB_TLS_CIPHER_ORDER_WORST_STATUS,
            full_score=scoring.WEB_TLS_CIPHER_ORDER_GOOD,
            model_score_field="cipher_order_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls cipher-order verdict good"
        self.tech_data = ""

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls cipher-order verdict bad"
        self.tech_data = ""

    def result_seclevel_bad(self, cipher_order_violation):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls cipher-order verdict seclevel-bad"
        self.tech_data = cipher_order_violation

    def result_score_warning(self, cipher_order_violation):
        self._status(STATUS_NOTICE)
        self.verdict = "detail web tls cipher-order verdict warning"
        self.tech_data = cipher_order_violation

    def result_score_info(self, cipher_order_violation):
        self._status(STATUS_INFO)
        self.verdict = "detail web tls cipher-order verdict warning"
        self.tech_data = cipher_order_violation

    def result_na(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls cipher-order verdict na"
        self.tech_data = ""


class WebTlsVersion(Subtest):
    def __init__(self):
        super(WebTlsVersion, self).__init__(
            name="tls_version",
            label="detail web tls version label",
            explanation="detail web tls version exp",
            init_tech_type="table_multi_col",
            tech_string="detail web tls version tech table",
            worst_status=scoring.WEB_TLS_PROTOCOLS_WORST_STATUS,
            full_score=scoring.WEB_TLS_PROTOCOLS_GOOD,
            model_score_field="protocols_score")

    def result_good(self,tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls version verdict good"
        self.tech_data = tech_data

    def result_phase_out(self, tech_data):
        self._status(STATUS_NOTICE)
        self.verdict = "detail web tls version verdict phase-out"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls version verdict bad"
        self.tech_data = tech_data


class WebTlsCompression(Subtest):
    def __init__(self):
        super(WebTlsCompression, self).__init__(
            name="tls_compression",
            label="detail web tls compression label",
            explanation="detail web tls compression exp",
            tech_string="detail web tls compression tech table",
            worst_status=scoring.WEB_TLS_COMPRESSION_WORST_STATUS,
            full_score=scoring.WEB_TLS_COMPRESSION_GOOD,
            model_score_field="compression_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls compression verdict good"
        self.tech_data = "detail tech data no"

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls compression verdict bad"
        self.tech_data = "detail tech data yes"


class WebTlsRenegotiationSecure(Subtest):
    def __init__(self):
        super(WebTlsRenegotiationSecure, self).__init__(
            name="renegotiation_secure",
            label="detail web tls renegotiation-secure label",
            explanation="detail web tls renegotiation-secure exp",
            tech_string="detail web tls renegotiation-secure tech table",
            worst_status=scoring.WEB_TLS_SECURE_RENEG_WORST_STATUS,
            full_score=scoring.WEB_TLS_SECURE_RENEG_GOOD,
            model_score_field="secure_reneg_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls renegotiation-secure verdict good"
        self.tech_data = "detail tech data yes"

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls renegotiation-secure verdict bad"
        self.tech_data = "detail tech data no"


class WebTlsRenegotiationClient(Subtest):
    def __init__(self):
        super(WebTlsRenegotiationClient, self).__init__(
            name="renegotiation_client",
            label="detail web tls renegotiation-client label",
            explanation="detail web tls renegotiation-client exp",
            tech_string="detail web tls renegotiation-client tech table",
            worst_status=scoring.WEB_TLS_CLIENT_RENEG_WORST_STATUS,
            full_score=scoring.WEB_TLS_CLIENT_RENEG_GOOD,
            model_score_field="client_reneg_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls renegotiation-client verdict good"
        self.tech_data = "detail tech data no"

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls renegotiation-client verdict bad"
        self.tech_data = "detail tech data yes"


class WebTlsCertTrust(Subtest):
    def __init__(self):
        super(WebTlsCertTrust, self).__init__(
            name="cert_trust",
            label="detail web tls cert-trust label",
            explanation="detail web tls cert-trust exp",
            tech_string="detail web tls cert-trust tech table",
            worst_status=scoring.WEB_TLS_TRUSTED_WORST_STATUS,
            full_score=scoring.WEB_TLS_TRUSTED_GOOD,
            model_score_field="cert_trusted_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls cert-trust verdict good"
        self.tech_data = ""

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls cert-trust verdict bad"
        self.tech_data = tech_data

    def result_could_not_test(self):
        self.verdict = "detail verdict could-not-test"


class WebTlsCertPubkey(Subtest):
    def __init__(self):
        super(WebTlsCertPubkey, self).__init__(
            name="cert_pubkey",
            label="detail web tls cert-pubkey label",
            explanation="detail web tls cert-pubkey exp",
            tech_string="detail web tls cert-pubkey tech table",
            worst_status=scoring.WEB_TLS_PUBKEY_WORST_STATUS,
            full_score=scoring.WEB_TLS_PUBKEY_GOOD,
            model_score_field="cert_pubkey_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls cert-pubkey verdict good"
        self.tech_data = ""

    def result_phase_out(self, tech_data):
        self._status(STATUS_NOTICE)
        self.verdict = "detail web tls cert-pubkey verdict phase-out"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls cert-pubkey verdict bad"
        self.tech_data = tech_data


class WebTlsCertSignature(Subtest):
    def __init__(self):
        super(WebTlsCertSignature, self).__init__(
            name="cert_signature",
            label="detail web tls cert-signature label",
            explanation="detail web tls cert-signature exp",
            init_tech_type="table_multi_col",
            tech_string="detail web tls cert-signature tech table",
            worst_status=scoring.WEB_TLS_SIGNATURE_WORST_STATUS,
            full_score=scoring.WEB_TLS_SIGNATURE_GOOD,
            model_score_field="cert_signature_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls cert-signature verdict good"
        self.tech_data = ""

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls cert-signature verdict bad"
        self.tech_data = tech_data


class WebTlsCertHostmatch(Subtest):
    def __init__(self):
        super(WebTlsCertHostmatch, self).__init__(
            name="cert_hostmatch",
            label="detail web tls cert-hostmatch label",
            explanation="detail web tls cert-hostmatch exp",
            tech_string="detail web tls cert-hostmatch tech table",
            worst_status=scoring.WEB_TLS_HOSTMATCH_WORST_STATUS,
            full_score=scoring.WEB_TLS_HOSTMATCH_GOOD,
            model_score_field="cert_hostmatch_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls cert-hostmatch verdict good"
        self.tech_data = ""

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls cert-hostmatch verdict bad"
        self.tech_data = tech_data


class WebTlsDaneExists(Subtest):
    def __init__(self):
        super(WebTlsDaneExists, self).__init__(
            name="dane_exists",
            label="detail web tls dane-exists label",
            explanation="detail web tls dane-exists exp",
            tech_string="detail web tls dane-exists tech table",
            worst_status=scoring.WEB_TLS_DANE_EXISTS_WORST_STATUS)

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls dane-exists verdict good"
        self.tech_data = tech_data

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls dane-exists verdict bad"
        self.tech_data = "detail tech data no"

    def result_bogus(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls dane-exists verdict bogus"
        self.tech_data = "detail tech data bogus"


class WebTlsDaneValid(Subtest):
    def __init__(self):
        super(WebTlsDaneValid, self).__init__(
            name="dane_valid",
            label="detail web tls dane-valid label",
            explanation="detail web tls dane-valid exp",
            tech_string="detail web tls dane-valid tech table",
            worst_status=scoring.WEB_TLS_DANE_VALID_WORST_STATUS,
            full_score=scoring.WEB_TLS_DANE_VALIDATED,
            model_score_field="dane_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls dane-valid verdict good"
        self.tech_data = "detail tech data yes"

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls dane-valid verdict bad"
        self.tech_data = "detail tech data no"


class WebTlsDaneRollover(Subtest):
    """
    .. note:: Disabled for now. May also disable DANE for web in the future.

    """
    def __init__(self):
        super(WebTlsDaneRollover, self).__init__(
            name="dane_rollover",
            label="detail web tls dane-rollover label",
            explanation="detail web tls dane-rollover exp",
            tech_string="detail web tls dane-rollover tech table",
            worst_status=scoring.WEB_TLS_DANE_ROLLOVER_WORST_STATUS)

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls dane-rollover verdict good"
        self.tech_data = "detail tech data yes"

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls dane-rollover verdict bad"
        self.tech_data = "detail tech data no"


class WebTlsZeroRTT(Subtest):
    def __init__(self):
        super(WebTlsZeroRTT, self).__init__(
            name="zero_rtt",
            label="detail web tls zero-rtt label",
            explanation="detail web tls zero-rtt exp",
            tech_string="detail web tls zero-rtt tech table",
            worst_status=scoring.WEB_TLS_ZERO_RTT_WORST_STATUS,
            full_score=scoring.WEB_TLS_ZERO_RTT_GOOD,
            model_score_field="zero_rtt_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls zero-rtt verdict good"
        self.tech_data = "detail tech data no"

    def result_na(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls zero-rtt verdict na"
        self.tech_data = "detail tech data no"

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls zero-rtt verdict bad"
        self.tech_data = "detail tech data yes"


class WebTlsOCSPStapling(Subtest):
    def __init__(self):
        super(WebTlsOCSPStapling, self).__init__(
            name="ocsp_stapling",
            label="detail web tls ocsp-stapling label",
            explanation="detail web tls ocsp-stapling exp",
            tech_string="detail web tls ocsp-stapling tech table",
            worst_status=scoring.WEB_TLS_OCSP_STAPLING_WORST_STATUS,
            full_score=scoring.WEB_TLS_OCSP_STAPLING_GOOD,
            model_score_field="ocsp_stapling_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls ocsp-stapling verdict good"
        self.tech_data = "detail tech data yes"

    def result_ok(self):
        self._status(STATUS_INFO)
        self.verdict = "detail web tls ocsp-stapling verdict ok"
        self.tech_data = "detail tech data no"

    def result_not_trusted(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls ocsp-stapling verdict bad"
        self.tech_data = "detail tech data no"


class WebTlsKexHashFunc(Subtest):
    def __init__(self):
        super(WebTlsKexHashFunc, self).__init__(
            name="kex_hash_func",
            label="detail web tls kex-hash-func label",
            explanation="detail web tls kex-hash-func exp",
            tech_string="detail web tls kex-hash-func tech table",
            worst_status=scoring.WEB_TLS_KEX_HASH_FUNC_WORST_STATUS,
            full_score=scoring.WEB_TLS_KEX_HASH_FUNC_GOOD,
            model_score_field="kex_hash_func_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web tls kex-hash-func verdict good"
        self.tech_data = "detail tech data yes"

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail web tls kex-hash-func verdict phase-out"
        self.tech_data = "detail tech data no"

    def result_unknown(self):
        self._status(STATUS_INFO)
        self.verdict = "detail web tls kex-hash-func verdict other"
        self.tech_data = "detail tech data not-applicable"


class MailTlsStarttlsExists(Subtest):
    def __init__(self):
        super(MailTlsStarttlsExists, self).__init__(
            name="starttls_exists",
            label="detail mail tls starttls-exists label",
            explanation="detail mail tls starttls-exists exp",
            tech_string="detail mail tls starttls-exists tech table",
            full_score=scoring.MAIL_TLS_STARTTLS_EXISTS_GOOD,
            worst_status=STATUS_INFO,
            model_score_field="tls_enabled_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_STARTTLS_EXISTS_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls starttls-exists verdict good"
        self.tech_data = "detail tech data yes"

    def result_bad(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls starttls-exists verdict bad"
        self.tech_data = "detail tech data no"

    def result_unreachable(self):
        self.was_tested()
        self._status(STATUS_ERROR, override=True)
        self.verdict = "detail mail tls starttls-exists verdict other"
        self.tech_data = "detail tech data not-reachable"

    def result_could_not_test(self):
        self.was_tested()
        self._status(STATUS_ERROR, override=True)
        self.verdict = "detail verdict could-not-test"
        self.tech_data = "detail tech data not-testable"

    def result_no_mailservers(self):
        self._status(STATUS_NOT_TESTED)
        self.verdict = "detail mail tls starttls-exists verdict other-2"
        self.tech_type = ""

    def result_null_mx(self):
        self._status(STATUS_NOT_TESTED)
        self.verdict = "detail mail tls starttls-exists verdict null-mx"
        self.tech_type = ""

    def result_no_null_mx(self):
        self._status(STATUS_INFO)
        self.verdict = "detail mail tls starttls-exists verdict no-null-mx"
        self.tech_type = ""

    def result_invalid_null_mx(self):
        self._status(STATUS_NOTICE, override=True)
        self.verdict = "detail mail tls starttls-exists verdict invalid-null-mx"
        self.tech_type = ""


class MailTlsFsParams(Subtest):
    def __init__(self):
        super(MailTlsFsParams, self).__init__(
            name="fs_params",
            label="detail mail tls fs-params label",
            explanation="detail mail tls fs-params exp",
            init_tech_type="table_multi_col",
            tech_string="detail mail tls fs-params tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_FS_GOOD,
            model_score_field="fs_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_FS_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls fs-params verdict good"
        self.tech_data = ""

    def result_phase_out(self, tech_data):
        self.was_tested()
        self._status(STATUS_NOTICE)
        self.verdict = "detail mail tls fs-params verdict phase-out"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls fs-params verdict bad"
        self.tech_data = tech_data

    def result_no_dh_params(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls fs-params verdict na"
        self.tech_data = ""


class MailTlsCiphers(Subtest):
    def __init__(self):
        super(MailTlsCiphers, self).__init__(
            name="tls_ciphers",
            label="detail mail tls ciphers label",
            explanation="detail mail tls ciphers exp",
            init_tech_type="table_multi_col",
            tech_string="detail mail tls ciphers tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_SUITES_GOOD,
            model_score_field="ciphers_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_SUITES_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls ciphers verdict good"
        self.tech_data = ""

    def result_phase_out(self, tech_data):
        self.was_tested()
        self._status(STATUS_NOTICE)
        self.verdict = "detail mail tls ciphers verdict phase-out"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls ciphers verdict bad"
        self.tech_data = tech_data


class MailTlsCipherOrder(Subtest):
    def __init__(self):
        super(MailTlsCipherOrder, self).__init__(
            name="tls_cipher_order",
            label="detail mail tls cipher-order label",
            explanation="detail mail tls cipher-order exp",
            init_tech_type="table_multi_col",
            tech_string="detail mail tls cipher-order tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_CIPHER_ORDER_GOOD,
            model_score_field="cipher_order_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_CIPHER_ORDER_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls cipher-order verdict good"
        self.tech_data = ""

    def result_bad(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls cipher-order verdict bad"
        self.tech_data = ""

    def result_seclevel_bad(self, cipher_order_violation):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls cipher-order verdict seclevel-bad"
        self.tech_data = cipher_order_violation

    def result_warning(self, cipher_order_violation):
        self.was_tested()
        self._status(STATUS_NOTICE)
        self.verdict = "detail mail tls cipher-order verdict warning"
        self.tech_data = cipher_order_violation

    def result_info(self, cipher_order_violation):
        self.was_tested()
        self._status(STATUS_INFO)
        self.verdict = "detail mail tls cipher-order verdict warning"
        self.tech_data = cipher_order_violation

    def result_na(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls cipher-order verdict na"
        self.tech_data = ""


class MailTlsVersion(Subtest):
    def __init__(self):
        super(MailTlsVersion, self).__init__(
            name="tls_version",
            label="detail mail tls version label",
            explanation="detail mail tls version exp",
            init_tech_type="table_multi_col",
            tech_string="detail mail tls version tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_PROTOCOLS_GOOD,
            model_score_field="protocols_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_PROTOCOLS_WORST_STATUS

    def result_phase_out(self, tech_data):
        self.was_tested()
        self._status(STATUS_NOTICE)
        self.verdict = "detail mail tls version verdict phase-out"
        self.tech_data = tech_data

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls version verdict good"
        self.tech_data = ""

    def result_bad(self, tech_data):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls version verdict bad"
        self.tech_data = tech_data


class MailTlsCompression(Subtest):
    def __init__(self):
        super(MailTlsCompression, self).__init__(
            name="tls_compression",
            label="detail mail tls compression label",
            explanation="detail mail tls compression exp",
            tech_string="detail mail tls compression tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_COMPRESSION_GOOD,
            model_score_field="compression_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_COMPRESSION_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls compression verdict good"
        self.tech_data = "detail tech data no"

    def result_bad(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls compression verdict bad"
        self.tech_data = "detail tech data yes"


class MailTlsRenegotiationSecure(Subtest):
    def __init__(self):
        super(MailTlsRenegotiationSecure, self).__init__(
            name="renegotiation_secure",
            label="detail mail tls renegotiation-secure label",
            explanation="detail mail tls renegotiation-secure exp",
            tech_string="detail mail tls renegotiation-secure tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_SECURE_RENEG_GOOD,
            model_score_field="secure_reneg_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_SECURE_RENEG_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls renegotiation-secure verdict good"
        self.tech_data = "detail tech data yes"

    def result_bad(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls renegotiation-secure verdict bad"
        self.tech_data = "detail tech data no"


class MailTlsRenegotiationClient(Subtest):
    def __init__(self):
        super(MailTlsRenegotiationClient, self).__init__(
            name="renegotiation_client",
            label="detail mail tls renegotiation-client label",
            explanation="detail mail tls renegotiation-client exp",
            tech_string="detail mail tls renegotiation-client tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_CLIENT_RENEG_GOOD,
            model_score_field="client_reneg_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_CLIENT_RENEG_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls renegotiation-client verdict good"
        self.tech_data = "detail tech data no"

    def result_bad(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls renegotiation-client verdict bad"
        self.tech_data = "detail tech data yes"


class MailTlsCertTrust(Subtest):
    def __init__(self):
        super(MailTlsCertTrust, self).__init__(
            name="cert_trust",
            label="detail mail tls cert-trust label",
            explanation="detail mail tls cert-trust exp",
            tech_string="detail mail tls cert-trust tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_TRUSTED_GOOD,
            model_score_field="cert_trusted_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_TRUSTED_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls cert-trust verdict good"
        self.tech_data = ""

    def result_bad(self, tech_data):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls cert-trust verdict bad"
        self.tech_data = tech_data

    def result_could_not_test(self):
        self.verdict = "detail verdict could-not-test"


class MailTlsCertPubkey(Subtest):
    def __init__(self):
        super(MailTlsCertPubkey, self).__init__(
            name="cert_pubkey",
            label="detail mail tls cert-pubkey label",
            explanation="detail mail tls cert-pubkey exp",
            tech_string="detail mail tls cert-pubkey tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_PUBKEY_GOOD,
            model_score_field="cert_pubkey_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_PUBKEY_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls cert-pubkey verdict good"
        self.tech_data = ""

    def result_phase_out(self, tech_data):
        self.was_tested()
        self._status(STATUS_NOTICE)
        self.verdict = "detail mail tls cert-pubkey verdict phase-out"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls cert-pubkey verdict bad"
        self.tech_data = tech_data


class MailTlsCertSignature(Subtest):
    def __init__(self):
        super(MailTlsCertSignature, self).__init__(
            name="cert_signature",
            label="detail mail tls cert-signature label",
            explanation="detail mail tls cert-signature exp",
            init_tech_type="table_multi_col",
            tech_string="detail mail tls cert-signature tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_SIGNATURE_GOOD,
            model_score_field="cert_signature_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_SIGNATURE_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls cert-signature verdict good"
        self.tech_data = ""

    def result_bad(self, tech_data):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls cert-signature verdict bad"
        self.tech_data = tech_data


class MailTlsCertHostmatch(Subtest):
    def __init__(self):
        super(MailTlsCertHostmatch, self).__init__(
            name="cert_hostmatch",
            label="detail mail tls cert-hostmatch label",
            explanation="detail mail tls cert-hostmatch exp",
            tech_string="detail mail tls cert-hostmatch tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_HOSTMATCH_GOOD,
            model_score_field="cert_hostmatch_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_HOSTMATCH_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls cert-hostmatch verdict good"
        self.tech_data = ""

    def result_bad(self, tech_data):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls cert-hostmatch verdict bad"
        self.tech_data = tech_data

    def result_has_daneTA(self, tech_data):
        self.was_tested()
        # HACK: for DANE-TA(2) and hostname mismatch!
        # Give a fail only if DANE-TA *is* present.
        self.status = STATUS_FAIL
        self.verdict = "detail mail tls cert-hostmatch verdict bad"
        self.tech_data = tech_data


class MailTlsZeroRTT(Subtest):
    def __init__(self):
        super(MailTlsZeroRTT, self).__init__(
            name="zero_rtt",
            label="detail mail tls zero-rtt label",
            explanation="detail mail tls zero-rtt exp",
            tech_string="detail mail tls zero-rtt tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_ZERO_RTT_GOOD,
            model_score_field="zero_rtt_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_ZERO_RTT_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls zero-rtt verdict good"
        self.tech_data = "detail tech data no"

    def result_na(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls zero-rtt verdict na"
        self.tech_data = "detail tech data no"

    def result_bad(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls zero-rtt verdict bad"
        self.tech_data = "detail tech data yes"


class MailTlsOCSPStapling(Subtest):
    """
    .. note:: Disabled for mail.

    """
    def __init__(self):
        super(MailTlsOCSPStapling, self).__init__(
            name="ocsp_stapling",
            label="detail mail tls ocsp-stapling label",
            explanation="detail mail tls ocsp-stapling exp",
            tech_string="detail mail tls ocsp-stapling tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_OCSP_STAPLING_GOOD,
            model_score_field="ocsp_stapling_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_OCSP_STAPLING_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls ocsp-stapling verdict good"
        self.tech_data = "detail tech data yes"

    def result_ok(self):
        self.was_tested()
        self._status(STATUS_INFO)
        self.verdict = "detail mail tls ocsp-stapling verdict ok"
        self.tech_data = "detail tech data no"

    def result_not_trusted(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls ocsp-stapling verdict bad"
        self.tech_data = "detail tech data no"


class MailTlsKexHashFunc(Subtest):
    def __init__(self):
        super(MailTlsKexHashFunc, self).__init__(
            name="kex_hash_func",
            label="detail mail tls kex-hash-func label",
            explanation="detail mail tls kex-hash-func exp",
            tech_string="detail mail tls kex-hash-func tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_KEX_HASH_FUNC_GOOD,
            model_score_field="kex_hash_func_score")

    def was_tested(self):
        self. worst_status = scoring.MAIL_TLS_KEX_HASH_FUNC_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls kex-hash-func verdict good"
        self.tech_data = "detail tech data yes"

    def result_bad(self):
        self.was_tested()
        self._status(STATUS_NOTICE)
        self.verdict = "detail mail tls kex-hash-func verdict phase-out"
        self.tech_data = "detail tech data no"

    def result_unknown(self):
        self.was_tested()
        self._status(STATUS_INFO)
        self.verdict = "detail mail tls kex-hash-func verdict other"
        self.tech_data = "detail tech data not-applicable"


class MailTlsDaneExists(Subtest):
    def __init__(self):
        super(MailTlsDaneExists, self).__init__(
            name="dane_exists",
            label="detail mail tls dane-exists label",
            explanation="detail mail tls dane-exists exp",
            tech_string="detail mail tls dane-exists tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_DANE_VALIDATED,
            model_score_field="dane_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_DANE_EXISTS_WORST_STATUS

    def result_good(self, tech_data):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls dane-exists verdict good"
        self.tech_data = tech_data

    def result_bad(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls dane-exists verdict bad"
        self.tech_data = "detail tech data no"

    def result_bogus(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls dane-exists verdict bogus"
        self.tech_data = "detail tech data bogus"


class MailTlsDaneValid(Subtest):
    def __init__(self):
        super(MailTlsDaneValid, self).__init__(
            name="dane_valid",
            label="detail mail tls dane-valid label",
            explanation="detail mail tls dane-valid exp",
            tech_string="detail mail tls dane-valid tech table",
            worst_status=STATUS_INFO,
            full_score=scoring.MAIL_TLS_DANE_VALIDATED,
            model_score_field="dane_score")

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_DANE_VALID_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls dane-valid verdict good"
        self.tech_data = "detail tech data yes"

    def result_bad(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls dane-valid verdict bad"
        self.tech_data = "detail tech data no"


class MailTlsDaneRollover(Subtest):
    def __init__(self):
        super(MailTlsDaneRollover, self).__init__(
            name="dane_rollover",
            label="detail mail tls dane-rollover label",
            explanation="detail mail tls dane-rollover exp",
            tech_string="detail mail tls dane-rollover tech table",
            worst_status=STATUS_INFO)

    def was_tested(self):
        self.worst_status = scoring.MAIL_TLS_DANE_ROLLOVER_WORST_STATUS

    def result_good(self):
        self.was_tested()
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail tls dane-rollover verdict good"
        self.tech_data = "detail tech data yes"

    def result_bad(self):
        self.was_tested()
        self._status(STATUS_FAIL)
        self.verdict = "detail mail tls dane-rollover verdict bad"
        self.tech_data = "detail tech data no"


# --- AUTH
class MailAuthDkim(Subtest):
    def __init__(self):
        super(MailAuthDkim, self).__init__(
            name="dkim",
            label="detail mail auth dkim label",
            explanation="detail mail auth dkim exp",
            tech_string="",
            init_tech_type="",
            worst_status=scoring.MAIL_AUTH_DKIM_WORST_STATUS,
            full_score=scoring.MAIL_AUTH_DKIM_PASS,
            model_score_field="dkim_score")

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail auth dkim verdict good"

    def result_bad(self):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail auth dkim verdict bad"

    def result_no_email(self):
        self.worst_status = STATUS_NOT_TESTED
        self._status(STATUS_NOT_TESTED)
        self.verdict = "detail mail auth dkim verdict no-email"


class MailAuthDmarc(Subtest):
    def __init__(self):
        super(MailAuthDmarc, self).__init__(
            name="dmarc",
            label="detail mail auth dmarc label",
            explanation="detail mail auth dmarc exp",
            tech_string="detail mail auth dmarc tech table",
            worst_status=scoring.MAIL_AUTH_DMARC_WORST_STATUS,
            full_score=scoring.MAIL_AUTH_DMARC_PASS,
            model_score_field="dmarc_score")
        # Fix for one line, one value data (not-tested case)
        self.tech_data = [[self.tech_data]]

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail auth dmarc verdict good"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail auth dmarc verdict bad"
        if tech_data:
            # More than one dmarc record. Show the records.
            self.tech_data = tech_data
        else:
            self.tech_data = ""
            self.tech_type = ""


class MailAuthDmarcPolicy(Subtest):
    def __init__(self):
        super(MailAuthDmarcPolicy, self).__init__(
            name="dmarc_policy",
            label="detail mail auth dmarc-policy label",
            explanation="detail mail auth dmarc-policy exp",
            tech_string="detail mail auth dmarc tech table",
            worst_status=scoring.MAIL_AUTH_DMARC_POLICY_WORST_STATUS,
            full_score=scoring.MAIL_AUTH_DMARC_POLICY_PASS,
            model_score_field="dmarc_policy_score")
        # Fix for one line, one value data (not-tested case)
        self.tech_data = [[self.tech_data]]

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail auth dmarc-policy verdict good"
        self.tech_type = ""

    def result_bad_syntax(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail auth dmarc-policy verdict bad"
        self.tech_data = tech_data

    def result_bad_policy(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail auth dmarc-policy verdict policy"
        self.tech_data = tech_data

    def result_invalid_external(self, tech_data):
        self._status(STATUS_NOTICE)
        self.verdict = "detail mail auth dmarc-policy verdict external"
        self.tech_data = tech_data


class MailAuthSpf(Subtest):
    def __init__(self):
        super(MailAuthSpf, self).__init__(
            name="spf",
            label="detail mail auth spf label",
            explanation="detail mail auth spf exp",
            tech_string="detail mail auth spf tech table",
            worst_status=scoring.MAIL_AUTH_SPF_WORST_STATUS,
            full_score=scoring.MAIL_AUTH_SPF_PASS,
            model_score_field="spf_score")
        # Fix for one line, one value data.
        self.tech_data = [[self.tech_data]]

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail auth spf verdict good"
        self.tech_data = [[tech_data]]

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail auth spf verdict bad"
        if tech_data:
            # More than one spf record. Show the records.
            self.tech_data = [[tech_data]]
        else:
            self.tech_data = ""
            self.tech_type = ""


class MailAuthSpfPolicy(Subtest):
    def __init__(self):
        super(MailAuthSpfPolicy, self).__init__(
            name="spf_policy",
            label="detail mail auth spf-policy label",
            explanation="detail mail auth spf-policy exp",
            tech_string="detail mail auth spf-policy tech table",
            worst_status=scoring.MAIL_AUTH_SPF_POLICY_WORST_STATUS,
            full_score=scoring.MAIL_AUTH_SPF_POLICY_PASS,
            model_score_field="spf_policy_score")
        # Fix for one line, one value data.
        self.tech_data = [[self.tech_data]]

    def result_good(self):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail mail auth spf-policy verdict good"
        self.tech_type = ""

    def result_bad_syntax(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail auth spf-policy verdict bad"
        self.tech_data = tech_data

    def result_bad_max_lookups(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail auth spf-policy verdict max-lookups"
        self.tech_data = tech_data

    def result_bad_policy(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail auth spf-policy verdict all"
        self.tech_data = tech_data

    def result_bad_include(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail auth spf-policy verdict include"
        self.tech_data = tech_data

    def result_bad_redirect(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail mail auth spf-policy verdict redirect"
        self.tech_data = tech_data


# --- APPSECPRIV
class WebAppsecprivHttpXFrame(Subtest):
    def __init__(self):
        super(WebAppsecprivHttpXFrame, self).__init__(
            name="http_x_frame",
            label="detail web appsecpriv http-x-frame label",
            explanation="detail web appsecpriv http-x-frame exp",
            tech_string="detail web appsecpriv http-x-frame tech table",
            worst_status=scoring.WEB_APPSECPRIV_X_FRAME_OPTIONS_WORST_STATUS,
            full_score=scoring.WEB_APPSECPRIV_X_FRAME_OPTIONS_GOOD,
            model_score_field="x_frame_options_score")

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web appsecpriv http-x-frame verdict good"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web appsecpriv http-x-frame verdict bad"
        self.tech_data = tech_data or ""


class WebAppsecprivHttpXXss(Subtest):
    def __init__(self):
        super(WebAppsecprivHttpXXss, self).__init__(
            name="http_x_xss",
            label="detail web appsecpriv http-x-xss label",
            explanation="detail web appsecpriv http-x-xss exp",
            tech_string="detail web appsecpriv http-x-xss tech table",
            worst_status=scoring.WEB_APPSECPRIV_X_XSS_PROTECTION_WORST_STATUS,
            full_score=scoring.WEB_APPSECPRIV_X_XSS_PROTECTION_GOOD,
            model_score_field="x_xss_protection_score")

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web appsecpriv http-x-xss verdict good"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web appsecpriv http-x-xss verdict bad"
        self.tech_data = tech_data or ""


class WebAppsecprivHttpXContentType(Subtest):
    def __init__(self):
        super(WebAppsecprivHttpXContentType, self).__init__(
            name="http_x_content_type",
            label="detail web appsecpriv http-x-content-type label",
            explanation="detail web appsecpriv http-x-content-type exp",
            tech_string="detail web appsecpriv http-x-content-type tech table",
            worst_status=(
                scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_WORST_STATUS),
            full_score=scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_GOOD,
            model_score_field="x_content_type_options_score")

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web appsecpriv http-x-content-type verdict good"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web appsecpriv http-x-content-type verdict bad"
        self.tech_data = tech_data or ""


class WebAppsecprivHttpCsp(Subtest):
    def __init__(self):
        super(WebAppsecprivHttpCsp, self).__init__(
            name="http_csp",
            label="detail web appsecpriv http-csp label",
            explanation="detail web appsecpriv http-csp exp",
            tech_string="detail web appsecpriv http-csp tech table",
            worst_status=(
                scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_WORST_STATUS),
            full_score=scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_GOOD,
            model_score_field="content_security_policy_score")

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = "detail web appsecpriv http-csp verdict good"
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = "detail web appsecpriv http-csp verdict bad"
        self.tech_data = tech_data or ""


class WebAppsecprivHttpReferrerPolicy(Subtest):
    def __init__(self):
        super(WebAppsecprivHttpReferrerPolicy, self).__init__(
            name="http_referrer_policy",
            label="detail web appsecpriv http-referrer-policy label",
            explanation="detail web appsecpriv http-referrer-policy exp",
            tech_string=(
                "detail web appsecpriv http-referrer-policy tech table"),
            worst_status=scoring.WEB_APPSECPRIV_REFERRER_POLICY_WORST_STATUS,
            full_score=scoring.WEB_APPSECPRIV_REFERRER_POLICY_GOOD,
            model_score_field="referrer_policy_score")

    def result_good(self, tech_data):
        self._status(STATUS_SUCCESS)
        self.verdict = (
            "detail web appsecpriv http-referrer-policy verdict good")
        self.tech_data = tech_data

    def result_bad(self, tech_data):
        self._status(STATUS_FAIL)
        self.verdict = (
            "detail web appsecpriv http-referrer-policy verdict bad")
        self.tech_data = tech_data or ""
