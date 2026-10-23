class QishenPureError(Exception):
    """Base error for the delivery package."""


class MissingDeviceStateError(QishenPureError):
    """Required device/session state was not supplied."""


class InvalidMaterialError(QishenPureError, ValueError):
    """Request-scoped pure-compute material is malformed."""
