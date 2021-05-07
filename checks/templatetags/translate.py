# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from collections import deque
import idna as IDNA

from django import template
from django.conf import settings
from django.template import Template
from django.utils.translation import ugettext as _

from ..scoring import STATUS_SUCCESS, STATUS_NOTICE, STATUS_GOOD_NOT_TESTED
from ..scoring import STATUS_NOT_TESTED, STATUS_INFO, STATUS_FAIL
from ..scoring import STATUSES_HTML_CSS_TEXT_MAP, STATUS_ERROR

register = template.Library()


@register.simple_tag(takes_context=True)
def translate(context, longname):
    contenttemplate = Template(_(longname))
    return contenttemplate.render(context)


@register.assignment_tag(takes_context=True)
def expand(context, pattern):
    contenttemplate = Template(pattern)
    return contenttemplate.render(context)


@register.assignment_tag(takes_context=True)
def lookup(context, pattern):
    contenttemplate = Template(pattern)
    return _(contenttemplate.render(context)+" .index").split()


@register.filter()
def idna(value):
    """
    Return the IDNA; value is str and may contain punnycode.

    """
    try:
        return IDNA.decode(value.encode("ascii"))
    except IDNA.IDNAError:
        return value


@register.simple_tag()
def maxlength(adjustment, *args):
    """
    Return the maximum length of *args.
    The result can be further manipulated with adjustment.

    .. note:: *args are expected to be strings.

    """
    if not args:
        return 0
    try:
        adjustment = int(adjustment)
    except ValueError:
        return 0

    return max([len(s) for s in args]) + adjustment


@register.inclusion_tag('details-table.html')
def render_details_table(headers, arguments):
    """
    Figure out the table's header and content and render them based on the
    given template.

    """
    headers = _(headers)
    headers = headers.split('|')

    table_length = len(headers)
    final_rows = []
    max_columns = 0
    for row_argument in arguments:
        row_generator = []
        # Create the row_generator for this row(s).
        for i, row_attribute in enumerate(row_argument):
            if i >= table_length:
                break

            if isinstance(row_attribute, list) and row_attribute:
                row_generator.append(deque(row_attribute))
            else:
                row_generator.append(deque([row_attribute]))

        # While at least one deque in the row_generator has data keep
        # building rows.
        while any(row_generator):
            row = []
            for column, cell_deque in enumerate(row_generator):
                if cell_deque:
                    value = cell_deque.popleft()
                    if not value:
                        value = _('results empty-argument-alt-text')
                    elif value in [
                            'detail tech data yes',
                            'detail tech data no',
                            'detail tech data secure',
                            'detail tech data insecure',
                            'detail tech data bogus',
                            'detail tech data not-applicable',
                            'detail tech data not-tested',
                            'detail tech data not-testable',
                            'detail tech data not-reachable',
                            'detail tech data phase-out',
                            'detail tech data sufficient',
                            'detail tech data insufficient'
                            ]:
                        value = _(value)
                    row.append(value)
                else:
                    if column == 0 and table_length > 1:
                        # The first column is most likely a hostname. Use
                        # ellipses for the further rows to indicate that data
                        # refers to the afforementioned hostname in previous
                        # rows.
                        row.append('...')
                    else:
                        # All other data get a dash.
                        row.append('-')

            max_columns = max(max_columns, column+1)
            final_rows.append(row)

    # Skip headers when the content is not that long.
    # Kind of a hack and mainly used for the 'security level' header
    # when there is no data to apply a security level to.
    headers = headers[:max_columns]

    return {
        'details_table_headers': headers,
        'details_table_rows': final_rows}


@register.filter()
def get_type(value):
    """
    Get the type of a Python object.

    """
    return type(value).__name__


@register.filter()
def get_testitem_div_class_and_text_status(testitem):
    status = testitem['status']
    if status not in (
            STATUS_SUCCESS, STATUS_NOTICE, STATUS_GOOD_NOT_TESTED,
            STATUS_NOT_TESTED, STATUS_INFO, STATUS_FAIL, STATUS_ERROR):
        status = STATUS_FAIL
    div_class = STATUSES_HTML_CSS_TEXT_MAP[status]
    text_status = _(f"results no-icon-status {div_class}")
    return div_class, text_status


@register.filter()
def probes_contain_dated_results(probes):
    """
    Place holder if we need to display a message for dated results in the
    future.

    """
    # for probe in probes:
    #     if something(probe):
    #         return True
    return False


@register.filter()
def addstr(str1, str2):
    """
    Concatenate two strings.

    """
    return "{}{}".format(str1, str2)


@register.filter()
def get_settings_value(name):
    """
    Return a settings value.
    Use it with caution. Don't expose sensitive settings.

    """
    return getattr(settings, name, "")
