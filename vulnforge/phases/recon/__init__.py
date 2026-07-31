"""Reconnaissance phase sub-package — re-exports all phases and constants for backward compatibility."""

from vulnforge.phases.recon.dns import phase_02_RESOLVE as phase_02_RESOLVE
from vulnforge.phases.recon.harvest import (
    phase_05_HARVEST as phase_05_HARVEST,
)
from vulnforge.phases.recon.harvest import (
    phase_05b_APISPEC as phase_05b_APISPEC,
)
from vulnforge.phases.recon.jsintel import (
    _JS_SECRET_PATTERNS as _JS_SECRET_PATTERNS,
)
from vulnforge.phases.recon.jsintel import (
    _SOURCE_MAP_RE as _SOURCE_MAP_RE,
)
from vulnforge.phases.recon.jsintel import (
    phase_06_JSINTEL as phase_06_JSINTEL,
)
from vulnforge.phases.recon.osint import (
    phase_84_WHOIS as phase_84_WHOIS,
)
from vulnforge.phases.recon.osint import (
    phase_85_ASN as phase_85_ASN,
)
from vulnforge.phases.recon.osint import (
    phase_86_DORK as phase_86_DORK,
)
from vulnforge.phases.recon.osint import (
    phase_87_SHODAN as phase_87_SHODAN,
)
from vulnforge.phases.recon.osint import (
    phase_88_EMPLOYEE as phase_88_EMPLOYEE,
)
from vulnforge.phases.recon.osint import (
    phase_89_PASSIVEDNS as phase_89_PASSIVEDNS,
)
from vulnforge.phases.recon.params import phase_07_PARAMS as phase_07_PARAMS
from vulnforge.phases.recon.scan import (
    phase_04_SCAN as phase_04_SCAN,
)
from vulnforge.phases.recon.scan import (
    phase_04b_TAKEOVER_VALIDATE as phase_04b_TAKEOVER_VALIDATE,
)
from vulnforge.phases.recon.scope import phase_00_SCOPE as phase_00_SCOPE
from vulnforge.phases.recon.subdomain import (
    phase_01_RECON as phase_01_RECON,
)
from vulnforge.phases.recon.subdomain import (
    phase_03_PERMUTE as phase_03_PERMUTE,
)
