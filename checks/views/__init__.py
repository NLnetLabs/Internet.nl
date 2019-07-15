# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import re

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.utils import translation
from django.utils.translation import ugettext as _

from checks import redis_id, simple_cache_page
from checks.views.shared import gethalloffamecache
from checks.views.shared import update_base_stats
from checks.views.shared import build_absolute_uri


def page404(request):
    return render(
        request, '404.html',
        dict(
            pageclass="error404",
            pagetitle=_("page404 title"),
            pagemenu="home"
        ))


@simple_cache_page
def indexpage(request):
    articles = _("article .index").split()
    articles = articles[0:6]
    cache_id = redis_id.home_stats_data.id
    novalue = "…"
    statswebsite = cache.get(cache_id.format("statswebsite"), novalue)
    statswebsitegood = cache.get(cache_id.format("statswebsitegood"), novalue)
    statswebsitebad = cache.get(cache_id.format("statswebsitebad"), novalue)
    statsmail = cache.get(cache_id.format("statsmail"), novalue)
    statsmailgood = cache.get(cache_id.format("statsmailgood"), novalue)
    statsmailbad = cache.get(cache_id.format("statsmailbad"), novalue)
    statsconnection = cache.get(cache_id.format("statsconnection"), novalue)
    statsconnectiongood = cache.get(
        cache_id.format("statsconnectiongood"), novalue)
    statsconnectionbad = cache.get(
        cache_id.format("statsconnectionbad"), novalue)
    update_base_stats()
    hof_date, hof_count, hof_entries = gethalloffamecache()
    return render(
        request, 'index.html',
        dict(
            pageclass="home",
            pagemenu="home",
            pagetitle=_("home pagetitle"),
            halloffame=hof_entries,
            count=hof_count,
            statswebsite=statswebsite,
            statswebsitegood=statswebsitegood,
            statswebsitebad=statswebsitebad,
            statsconnection=statsconnection,
            statsconnectiongood=statsconnectiongood,
            statsconnectionbad=statsconnectionbad,
            statsmail=statsmail,
            statsmailgood=statsmailgood,
            statsmailbad=statsmailbad,
            latest=hof_date,
            articles=articles
        ))


# URL: /clear/<dname>
def clear(request, dname):
    url = dname.lower()
    if url in settings.CACHE_RESET_WHITELIST:
        for test in [
                "mail_auth", "dnssec", "web_ipv6", "mail_ipv6",
                "web_tls", "web_appsecpriv"]:
            cache.delete(redis_id.dom_task.id.format(url, test))
        return HttpResponse("ok")
    return HttpResponse("nope")


def testconnectionpage(request):
    return render(
        request, 'test-connection.html',
        dict(pagemenu="faqs", pagetitle=_("base test connection title")))


def testsitepage(request):
    return render(
        request, 'test-site.html',
        dict(pagemenu="faqs", pagetitle=_("base test website title")))


def testmailpage(request):
    return render(
        request, 'test-mail.html',
        dict(pagemenu="faqs", pagetitle=_("base test mail title")))


def disclosurepage(request):
    return render(
        request, 'disclosure.html',
        dict(pagemenu="home", pagetitle=_("base disclosure")))


def copyrightpage(request):
    return render(
        request, 'copyright.html',
        dict(pagemenu="home", pagetitle=_("base copyright")))


def privacypage(request):
    return render(
        request, 'privacy.html',
        dict(pagemenu="home", pagetitle=_("base privacy")))


def aboutpage(request):
    return render(
        request, 'about.html',
        dict(pagemenu="about", pageclass="contact", pagetitle=_("base about")))


def partnerspage(request):
    return render(
        request, 'partners.html',
        dict(pagemenu="about", pagetitle=_("base partners")))


def faqindexpage(request):
    return render(
        request, 'faqindex.html',
        dict(pagemenu="faqs", pageclass="faqs", pagetitle=_("base faqs")))


def faqreport(request):
    return render(
        request, 'faq-report.html',
        dict(
            pagemenu="faqs",
            pageclass="faqs",
            pagetitle=_("faqs report title")
        ))


def faqarticlepage(request, subject):
    title = "faqs " + subject + " title"
    content = "faqs " + subject + " content"
    return render(
        request, 'faqarticle.html',
        dict(
            pagemenu="faqs",
            pageclass="faqs",
            pagetitle=_(title),
            title=title,
            content=content
        ))


def blogindexpage(request):
    return redirect('/articles/')


def blogarticlepage(request, author, article):
    return redirect('/article/'+article)


def newsindexpage(request):
    return redirect('/article/')


def newsarticlepage(request, article):
    return redirect('/article/'+article)


def articlespage(request):
    articles = _("article .index").split()
    article = articles[0]
    return redirect('/article/'+article)


def articleindexpage(request):
    articles = _("article .index").split()
    if len(articles) < 1:
        articles = []
    return render(
        request, 'articles.html',
        dict(
            pageclass="newsitem",
            pagetitle=_("base news"),
            pagemenu="news",
            articles=articles
        ))


def articlepage(request, article):
    articles = _("article .index").split()
    articles = articles[0:6]
    title = "article " + article + " title"
    date = "article " + article + " date"
    lead = "article " + article + " lead"
    body = "article " + article + " body"
    author = _("article " + article + " author")
    if author == "article " + article + " author":
        author = ""
    return render(
        request, 'article.html',
        dict(
            pageclass="newsitem",
            pagetitle=_(title),
            pagemenu="news",
            article=article,
            articles=articles,
            date=date,
            title=title,
            lead=lead,
            author=author,
            body=body
        ))


@simple_cache_page
def halloffamepage(request):
    hof_date, hof_count, hof_entries = gethalloffamecache(100000)
    # We don't show all the records in the HoF
    hof_count = len(hof_entries)
    return render(
        request, 'halloffame.html',
        dict(
            pageclass="hall-of-fame",
            pagetitle=_("base halloffame"),
            pagemenu="halloffame",
            latest=hof_date,
            count=hof_count,
            halloffame=hof_entries
        ))


def change_language(request):
    """
    Redirect to a new hostname when the user wishes for a language change.
    The user will be redirected to the same page he was before.

    """
    if request.method == 'POST':
        hostname = request.get_host().split(':')[0]
        previous_page = request.POST.get('previous-page', '/')

        # The News category may have articles available only for certain
        # languages, so we redirect to the News index instead.
        # BAD: the urls are coded in code, rather than to the sole knowledge
        #      of the urls.py definition.
        news_url = re.match(r"^/news/.*$", previous_page)
        if news_url:
            previous_page = '/news/'
        news_url = re.match(r"^/blogs/.*$", previous_page)
        if news_url:
            previous_page = '/blogs/'
        news_url = re.match(r"^/blogarticle/.*$", previous_page)
        if news_url:
            previous_page = '/blogarticle/'
        news_url = re.match(r"^/article/.*$", previous_page)
        if news_url:
            previous_page = '/article/'

        new_language = request.POST.get('language')
        if new_language and translation.check_for_language(new_language):
            url_regex = re.compile("^(?P<protocol>http[s]?://).*$")
            uri = build_absolute_uri(request)
            protocol = url_regex.match(uri).group('protocol')

            # If the previous language is in the host remove it.
            # Also if the hostname starts with 'www.' (may appear in the
            # default language site) remove it so that the language prefix gets
            # applied to the domain name.
            previous_language = hostname.split('.', 1)[0]
            if (translation.check_for_language(previous_language) or
                    previous_language == 'www'):
                no_language_host = request.get_host().replace(
                        previous_language + '.', '', 1)
            else:
                no_language_host = request.get_host()

            language_prefix = new_language + '.'
            response = HttpResponseRedirect(protocol + language_prefix +
                                            no_language_host + previous_page)
        else:
            response = HttpResponseRedirect(previous_page)

        return response
    return HttpResponseRedirect('/')
