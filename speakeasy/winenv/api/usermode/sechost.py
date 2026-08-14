# Copyright (C) 2026 Speakeasy-X

from .advapi32 import AdvApi32

from .. import api


class Sechost(AdvApi32):
    """
    Implements exported functions from sechost.dll.

    sechost.dll re-exports the service, eventing and security APIs from
    advapi32.dll, so all real AdvApi32 handlers are reused directly.
    """

    name = "sechost"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata
