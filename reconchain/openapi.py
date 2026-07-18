"""OpenAPI 3.0 specification generator for ReconChain REST API.

Generates and serves the OpenAPI specification for API documentation,
client generation, and Swagger UI integration.

Usage:
    from reconchain.openapi import get_spec, generate_spec_file
    spec = get_spec()
    generate_spec_file(outdir)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from reconchain.utils import ensure, log


_SPEC_PATH = Path(__file__).parent / "openapi.json"


def get_spec() -> Dict[str, Any]:
    """Load the OpenAPI specification from the bundled JSON file.

    Returns:
        The full OpenAPI 3.0 specification as a dictionary.
    """
    if _SPEC_PATH.exists():
        try:
            return json.loads(_SPEC_PATH.read_text(encoding="utf-8"))
        except Exception as e:
            log("warn", f"openapi: failed to load spec: {e}")
    return _build_spec()


def _build_spec() -> Dict[str, Any]:
    """Build a minimal OpenAPI spec programmatically (fallback)."""
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "ReconChain REST API",
            "version": "3.1.0",
            "description": "Security reconnaissance and vulnerability scanning API",
        },
        "servers": [{"url": "http://localhost:8080"}],
        "paths": {},
    }


def generate_spec_file(outdir: Path) -> Path:
    """Write the OpenAPI spec to a file.

    Args:
        outdir: Directory to write the spec file.

    Returns:
        Path to the generated openapi.json.
    """
    spec = get_spec()
    out = ensure(outdir / "openapi.json")
    out.write_text(json.dumps(spec, indent=2))
    log("ok", f"openapi: spec written → {out}")
    return out


def get_swagger_ui_html(spec_url: str = "/api/v1/openapi.json") -> str:
    """Generate HTML for embedded Swagger UI documentation.

    Args:
        spec_url: URL path to the OpenAPI JSON spec.

    Returns:
        HTML string for a Swagger UI page.
    """
    from html import escape as _html_escape
    safe_url = _html_escape(spec_url, quote=True)
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>ReconChain API - Swagger UI</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" integrity="sha384-BQ4n5pE5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y" crossorigin="anonymous">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js" integrity="sha384-BQ4n5pE5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y" crossorigin="anonymous"></script>
    <script>
        SwaggerUIBundle({{
            url: "{safe_url}",
            dom_id: '#swagger-ui',
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIBundle.SwaggerUIStandalonePreset
            ],
            layout: "BaseLayout"
        }});
    </script>
</body>
</html>"""


def get_redoc_html(spec_url: str = "/api/v1/openapi.json") -> str:
    """Generate HTML for embedded ReDoc documentation.

    Args:
        spec_url: URL path to the OpenAPI JSON spec.

    Returns:
        HTML string for a ReDoc page.
    """
    from html import escape as _html_escape
    safe_url = _html_escape(spec_url, quote=True)
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>ReconChain API - Documentation</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700,900|Roboto:300,400,700" rel="stylesheet">
    <style>
        body {{ margin: 0; padding: 0; }}
    </style>
</head>
<body>
    <redoc spec-url="{safe_url}"></redoc>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js" integrity="sha384-BQ4n5pE5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y" crossorigin="anonymous"></script>
</body>
</html>"""


def get_api_endpoints() -> Dict[str, Dict[str, Any]]:
    """Return a summary of all API endpoints.

    Returns:
        Dict mapping endpoint path → {method, summary, tags}.
    """
    spec = get_spec()
    endpoints: Dict[str, Dict[str, Any]] = {}
    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if method in ("get", "post", "put", "delete", "patch"):
                endpoints[f"{method.upper()} {path}"] = {
                    "summary": details.get("summary", ""),
                    "tags": details.get("tags", []),
                    "operationId": details.get("operationId", ""),
                }
    return endpoints


def validate_spec(spec: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Validate the OpenAPI specification structure.

    Returns:
        Dict with 'valid' bool and optional 'errors' list.
    """
    if spec is None:
        spec = get_spec()

    errors: list = []

    # Required fields
    if "openapi" not in spec:
        errors.append("Missing 'openapi' version field")
    if "info" not in spec:
        errors.append("Missing 'info' object")
    elif "title" not in spec.get("info", {}):
        errors.append("Missing 'info.title'")
    elif "version" not in spec.get("info", {}):
        errors.append("Missing 'info.version'")

    if "paths" not in spec:
        errors.append("Missing 'paths' object")

    # Validate path operations
    for path, methods in spec.get("paths", {}).items():
        if not path.startswith("/"):
            errors.append(f"Path must start with '/': {path}")
        for method, details in methods.items():
            if method.startswith("x-"):
                continue  # Extension
            if method.lower() not in ("get", "post", "put", "delete", "patch", "head", "options"):
                errors.append(f"Invalid HTTP method '{method}' in path '{path}'")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "path_count": len(spec.get("paths", {})),
        "info": spec.get("info", {}),
    }
