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
