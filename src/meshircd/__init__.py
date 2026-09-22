"""meshircd -- a small, self-contained IRC server.

Standard library only: no framework, no runtime dependencies, no
virtualenv required to run it.
"""

from .server import VERSION

__version__ = VERSION
__all__ = ["VERSION", "__version__"]
