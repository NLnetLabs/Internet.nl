# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.db import transaction

from . import SetupUnboundContext, shared
from .dispatcher import check_registry, post_callback_hook
from .http_headers import HeaderCheckerXContentTypeOptions
from .http_headers import HeaderCheckerXXssProtection
from .http_headers import HeaderCheckerReferrerPolicy
from .http_headers import HeaderCheckerXFrameOptions
from .http_headers import HeaderCheckerContentSecurityPolicy
from .http_headers import http_headers_check
from .shared import results_per_domain, aggregate_subreports
from .. import categories
from .. import batch, batch_shared_task
from ..models import WebTestAppsecpriv, DomainTestAppsecpriv
from .. import scoring


@shared_task(bind=True)
def web_callback(self, results, domain, req_limit_id):
    """
    Save results in db.

    """
    category = categories.WebAppsecpriv()
    webdomain, results = callback(results, domain, category)
    # Always calculate scores on saving.
    from ..probes import web_probe_appsecpriv
    web_probe_appsecpriv.rated_results_by_model(webdomain)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_web_callback(self, results, domain):
    """
    Save results in the DB.

    """
    category = categories.WebAppsecpriv()
    webdomain, results = callback(results, domain, category)
    # Always calculate scores on saving.
    from ..probes import batch_web_probe_appsecpriv
    batch_web_probe_appsecpriv.rated_results_by_model(webdomain)
    batch.scheduler.batch_callback_hook(webdomain, self.request.id)


@transaction.atomic
def callback(results, domain, category):
    """
    Get the results, create the necessary tables and commit in the DB.

    """
    results = results_per_domain(results)
    webdomain = WebTestAppsecpriv(domain=domain)
    webdomain.save()
    if len(results.keys()) > 0:
        for addr, res in results.items():
            dtappsecpriv = DomainTestAppsecpriv(domain=addr)
            save_results(dtappsecpriv, res, addr, domain)
            build_report(dtappsecpriv, category)
            dtappsecpriv.save()
            webdomain.webtestset.add(dtappsecpriv)
    build_summary_report(webdomain, category)
    webdomain.save()
    return webdomain, results


web_registered = check_registry(
    "web_appsecpriv", web_callback, shared.resolve_a_aaaa)
batch_web_registered = check_registry(
    "batch_web_appsecpriv", batch_web_callback, shared.batch_resolve_a_aaaa)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def web_appsecpriv(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_appsecpriv(af_ip_pairs, url, self, *args, **kwargs)


@batch_web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_web_appsecpriv(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_appsecpriv(af_ip_pairs, url, self, *args, **kwargs)


def save_results(model, results, addr, domain):
    """
    Save results in the DB.

    """
    for testname, result in results:
        if testname == "http_headers":
            model.server_reachable = result.get("server_reachable", True)
            if model.server_reachable:
                model.x_frame_options_enabled = result.get(
                    "x_frame_options_enabled")
                model.x_frame_options_score = result.get(
                    "x_frame_options_score")
                model.x_frame_options_values = result.get(
                    "x_frame_options_values")
                model.x_content_type_options_enabled = result.get(
                    "x_content_type_options_enabled")
                model.x_content_type_options_score = result.get(
                    "x_content_type_options_score")
                model.x_content_type_options_values = result.get(
                    "x_content_type_options_values")
                model.x_xss_protection_enabled = result.get(
                    "x_xss_protection_enabled")
                model.x_xss_protection_score = result.get(
                    "x_xss_protection_score")
                model.x_xss_protection_values = result.get(
                    "x_xss_protection_values")
                model.referrer_policy_enabled = result.get(
                    "referrer_policy_enabled")
                model.referrer_policy_score = result.get(
                    "referrer_policy_score")
                model.referrer_policy_values = result.get(
                    "referrer_policy_values")
                model.content_security_policy_enabled = result.get(
                    "content_security_policy_enabled")
                model.content_security_policy_score = result.get(
                    "content_security_policy_score")
                model.content_security_policy_values = result.get(
                    "content_security_policy_values")

    model.save()


def build_report(model, category):
    """
    Build the report.

    """
    category = category.__class__()
    if model.server_reachable:
        if model.x_frame_options_enabled:
            category.subtests['http_x_frame'].result_good(
                model.x_frame_options_values)
        else:
            category.subtests['http_x_frame'].result_bad(
                model.x_frame_options_values)

        # Do not include XSS in the report.
        # TODO: Will be removed altogether in the future.
        #if model.x_xss_protection_enabled:
        #    category.subtests['http_x_xss'].result_good(
        #        model.x_xss_protection_values)
        #else:
        #    category.subtests['http_x_xss'].result_bad(
        #        model.x_xss_protection_values)

        if model.referrer_policy_enabled:
            if model.referrer_policy_score == WEB_APPSECPRIV_REFERRER_POLICY_INFO:
                category.subtests['http_referrer_policy'].result_info(
                    model.referrer_policy_values)
            else:
                category.subtests['http_referrer_policy'].result_good(
                    model.referrer_policy_values)
        else:
            category.subtests['http_referrer_policy'].result_bad(
                model.referrer_policy_values)

        if model.content_security_policy_enabled:
            category.subtests['http_csp'].result_good(
                model.content_security_policy_values)
        else:
            category.subtests['http_csp'].result_bad(
                model.content_security_policy_values)

        if model.x_content_type_options_enabled:
            category.subtests['http_x_content_type'].result_good(
                model.x_content_type_options_values)
        else:
            category.subtests['http_x_content_type'].result_bad(
                model.x_content_type_options_values)

    model.report = category.gen_report()


def build_summary_report(testappsecpriv, category):
    """
    Build the summary report for all the IP addresses.

    """
    server_set = testappsecpriv.webtestset

    subreports = {}
    for server_test in server_set.all():
        subreports[server_test.domain] = server_test.report

    appsecpriv_report = category.__class__().gen_report()
    aggregate_subreports(subreports, appsecpriv_report)
    testappsecpriv.report = appsecpriv_report


def do_web_appsecpriv(af_ip_pairs, url, task, *args, **kwargs):
    try:
        results = {}
        header_checkers = [
            HeaderCheckerContentSecurityPolicy(),
            HeaderCheckerXFrameOptions(),
            HeaderCheckerReferrerPolicy(),
            HeaderCheckerXXssProtection(),
            HeaderCheckerXContentTypeOptions(),
        ]
        for af_ip_pair in af_ip_pairs:
            results[af_ip_pair[1]] = http_headers_check(
                af_ip_pair, url, header_checkers, task)

    except SoftTimeLimitExceeded:
        for af_ip_pair in af_ip_pairs:
            if not results.get(af_ip_pair[1]):
                d = {'server_reachable': False}
                for h in header_checkers:
                    d.update(h.get_negative_values())
                results[af_ip_pair[1]] = d

    return ('http_headers', results)
