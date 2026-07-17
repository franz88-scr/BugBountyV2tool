"""Infrastructure phases — re-exported from focused submodules for backward compatibility.

This module previously contained 4,009 lines across 47 phase functions.
It has been split into focused modules for better maintainability:
  - origin_cloud.py:  14-ORIGIN, 18-CLOUD, 46-BUCKET, 50-BUCKET-PERMS
  - secrets_git.py:   15-SECRETS, 19-GIT, 79-SECRETDIFF
  - graphql_chain.py: 20-GRAPHQL, 44-CHAIN, 45-EVIDENCE
  - injection_misc.py: 22-NOSQLI, 25-XXE, 26-CMDINJECT, 27-SSPP, 29-DEPCHECK,
                       42-LDAP, 43-DESERIAL, 66-SSRF-FULL, 69-DNSZT, 70-PORTFULL
  - web_infra.py:     47-CDN, 48-CONTENT, 49-FRAMEWORKS, 51-HPP, 52-SERVERLESS,
                       53-CSP, 55-CSV-INJECT, 56-EXPOSED-DB, 57-DEFAULT-CREDS, 58-HOST-INJECT
  - email_misc.py:    59-EMAIL-SEC, 60-SMTP-ENUM, 62-LOG-INJECT, 63-DOC-ATTACK,
                       64-IDEMPOTENCY, 67-PATHNORM, 71-EMHARVEST, 72-ACCOUNTENUM,
                       74-GHTOOLS, 75-MOBILEAPI, 76-WORKFLOW, 77-CACHEKEY,
                       78-FILEUPLOADADV, 81-IDORFUZZ
"""
from reconchain.phases.origin_cloud import (
    phase_14_ORIGIN,
    phase_18_CLOUD,
    phase_46_BUCKET,
    phase_50_BUCKET_PERMS,
)
from reconchain.phases.secrets_git import (
    phase_15_SECRETS,
    phase_19_GIT,
    phase_79_SECRETDIFF,
)
from reconchain.phases.graphql_chain import (
    phase_20_GRAPHQL,
    phase_44_CHAIN,
    phase_45_EVIDENCE,
)
from reconchain.phases.injection_misc import (
    _parse_semver,
    _semver_lt,
    phase_22_NOSQLI,
    phase_25_XXE,
    phase_26_CMDINJECT,
    phase_27_SSPP,
    phase_29_DEPCHECK,
    phase_42_LDAP,
    phase_43_DESERIAL,
    phase_66_SSRF_FULL,
    phase_69_DNSZT,
    phase_70_PORTFULL,
)
from reconchain.phases.web_infra import (
    phase_47_CDN,
    phase_48_CONTENT,
    phase_49_FRAMEWORKS,
    phase_51_HPP,
    phase_52_SERVERLESS,
    phase_53_CSP,
    phase_55_CSV_INJECT,
    phase_56_EXPOSED_DB,
    phase_57_DEFAULT_CREDS,
    phase_58_HOST_INJECT,
)
from reconchain.phases.email_misc import (
    phase_59_EMAIL_SEC,
    phase_60_SMTP_ENUM,
    phase_62_LOG_INJECT,
    phase_63_DOC_ATTACK,
    phase_64_IDEMPOTENCY,
    phase_67_PATHNORM,
    phase_71_EMHARVEST,
    phase_72_ACCOUNTENUM,
    phase_74_GHTOOLS,
    phase_75_MOBILEAPI,
    phase_76_WORKFLOW,
    phase_77_CACHEKEY,
    phase_78_FILEUPLOADADV,
    phase_81_IDORFUZZ,
)
