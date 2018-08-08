"""
mixins.sentry

A RequestHandler mixin for sending exceptions to Sentry

"""
version_info = (1, 1, 2)
__version__ = '.'.join(str(v) for v in version_info)


import logging
import math
import os
import re
import time
try:
    from urllib import parse
except ImportError:  # pragma no cover
    import urlparse as parse

import raven
from raven._compat import string_types, text_type
from raven.processors import SanitizePasswordsProcessor
import raven.contrib.tornado


LOGGER = logging.getLogger(__name__)
SENTRY_CLIENT = 'sentry_client'

# This matches the userinfo production from RFC3986 with some extra
# leniancy to account for poorly formed URLs.  For example, it lets
# you include braces and other things in the password section.
URI_RE = re.compile(r"^[\w\+\-]+://"
                    r"[-a-z0-9._~!$&'()*+,;=%]+:"
                    r"([^@]+)"
                    r"@",
                    re.IGNORECASE)

_sentry_warning_issued = False


class SanitizeEmailsProcessor(SanitizePasswordsProcessor):
    """
    Remove all email addresses from the payload sent to sentry.

    """

    FIELDS = frozenset(['email', 'email_address'])
    VALUES_RE = re.compile(r"""
    ((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"
      (?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|
       \\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")
      @
      (?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]
      (?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|
       [01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|
       [a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|
       \\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))
    """, re.VERBOSE ^ re.IGNORECASE)  # RFC5322

    def sanitize(self, key, value):
        if value is None:
            return

        if isinstance(value, string_types):
            return self.VALUES_RE.sub(self.MASK, value)

        if not key:  # key can be a NoneType
            return value

        # Just in case we have bytes here, we want to make them into text
        # properly without failing so we can perform our check.
        if isinstance(key, bytes):
            key = key.decode('utf-8', 'replace')
        else:
            key = text_type(key)

        key = key.lower()
        for field in self.FIELDS:
            if field in key:
                # store mask as a fixed length for security
                return self.MASK
        return value


class SentryMixin(raven.contrib.tornado.SentryMixin):
    """
    Report unexpected exceptions to Sentry.

    Mix this in over a :class:`tornado.web.RequestHandler` to report
    unhandled exceptions to Sentry so that you can figure out what
    went wrong.
    """

    @staticmethod
    def _strip_uri_passwords(values):
        for key in values.keys():
            matches = URI_RE.search(values[key])
            if matches:
                values[key] = values[key].replace(matches.group(1), '****')
        return values

    def get_sentry_extra_info(self):
        extra = super(SentryMixin).get_sentry_extra_info()
        extra.update({
            'extra': {
                'http_host': self.request.host,
                'remote_ip': self.request.remote_ip,
                'handler': '{}.{}'.format(__name__, self.__class__.__name__)
            },
            'time_spent': math.ceil(
                (time.time() - self.request._start_time) * 1000
            ),
            'env': self._strip_uri_passwords(dict(os.environ)),
            'logger': 'sprockets.mixins.sentry'
        })
        return extra


def install(application, **kwargs):
    """
    Call this to install a sentry client into a Tornado application.

    :param tornado.web.Application application: the application to
        install the client into.
    :param kwargs: keyword parameters to pass to the
        :class:`raven.base.Client` initializer.

    :returns: :data:`True` if the client was installed by this call
        and :data:`False` otherwise.

    This function should be called to initialize the Sentry client
    for your application.  It will be called automatically with the
    default parameters by :class:`.SentryMixin` if you do not call
    it during the creation of your application.  You should install
    the client explicitly so that you can set at least the following
    properties:

    - **include_paths** list of python modules to include in tracebacks.
      This function ensures that ``raven``, ``sprockets``, ``sys``, and
      ``tornado`` are included but you probably want to include additional
      packages.

    - **release** the version of the application that is running

    See `the raven documentation`_ for additional information.

    .. _the raven documentation: https://docs.getsentry.com/hosted/clients/
       python/advanced/#client-arguments

    """
    if get_client(application) is not None:
        LOGGER.warning('sentry client is already installed')
        return False

    sentry_dsn = kwargs.pop('dsn', os.environ.get('SENTRY_DSN'))
    if sentry_dsn is None:
        global _sentry_warning_issued
        if not _sentry_warning_issued:
            LOGGER.info('sentry DSN not found, not installing client')
            _sentry_warning_issued = True
        setattr(application, 'sentry_client', None)
        return False

    # ``include_paths`` has two purposes:
    # 1. it tells sentry which parts of the stack trace are considered
    #    part of the application for use in the UI
    # 2. it controls which modules are included in the version dump
    include_paths = set(kwargs.pop('include_paths', []))
    include_paths.update(['raven', 'sprockets', 'sys', 'tornado', __name__])
    kwargs['include_paths'] = list(include_paths)

    # ``exclude_paths`` tells the sentry UI which modules to exclude
    # from the "In App" view of the traceback.
    exclude_paths = set(kwargs.pop('exclude_paths', []))
    exclude_paths.update(['raven', 'sys', 'tornado'])
    kwargs['exclude_paths'] = list(exclude_paths)

    if os.environ.get('ENVIRONMENT'):
        kwargs.setdefault('environment', os.environ['ENVIRONMENT'])

    client = raven.Client(sentry_dsn, **kwargs)
    setattr(application, 'sentry_client', client)

    return True


def get_client(application):
    """
    Retrieve the sentry client for `application`.

    :param tornado.web.Application application: application to retrieve
        the sentry client for.
    :returns: a :class:`raven.base.Client` instance or :data:`None`
    :rtype: raven.base.Client

    """
    try:
        return application.sentry_client
    except AttributeError:
        return None
