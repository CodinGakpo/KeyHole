"""Secondary DLP backstop.

IMPORTANT: this is *defense in depth*, not the guarantee. The guarantee is the bandwidth bound
of the typed exit (see :mod:`keyhole.schema`). The scanners here run over the small released
output to catch obvious mistakes (a secret printed in plain sight); they are explicitly not
relied upon to stop a determined adversary, because content scanning is defeated by
encrypt-before-emit. Never describe these as the confidentiality guarantee.
"""

from keyhole.dlp.pii_scan import scan_pii
from keyhole.dlp.secret_scan import Finding, scan_secrets

__all__ = ["scan_secrets", "scan_pii", "Finding"]
