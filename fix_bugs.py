"""Fix all critical bugs described in the task."""
import re
import sys
from pathlib import Path


def find_except_body(lines: list[str], start_idx: int, keyword_indent: str) -> list[int]:
    """Return indices of lines in the except body (exclusive end)."""
    body_lines = []
    for j in range(start_idx + 1, len(lines)):
        if not lines[j].strip() or lines[j].strip().startswith('#'):
            continue
        # Check if this line is at the same or lesser indentation than the except keyword
        line_indent = re.match(r'^(\s*)', lines[j]).group(1)
        if len(line_indent) <= len(keyword_indent) and lines[j].strip():
            break  # End of body
        body_lines.append(j)
    return body_lines


def body_has_pass_or_continue(lines: list[str], body_indices: list[int]) -> bool:
    """Check if the except body contains `pass` or `continue` as a statement (not in string)."""
    for idx in body_indices:
        stripped = lines[idx].strip()
        # Check if this line is a `pass` or `continue` statement (possibly with comment)
        if re.match(r'^(pass|continue)\s*(#.*)?$', stripped):
            return True
    # Also check for multi-line: some cases have `findings.append(...)` then `continue` on next line
    # We already check each line individually above, so multi-line is handled if `continue` is on its own line
    return False


def body_has_raise(lines: list[str], body_indices: list[int]) -> bool:
    """Check if the except body contains a `raise` statement."""
    for idx in body_indices:
        stripped = lines[idx].strip()
        if re.match(r'^raise\s', stripped) or stripped == 'raise':
            return True
    return False


def fix_cancelled_error(filepath: Path) -> bool:
    """Add `except asyncio.CancelledError: raise` before `except Exception:` blocks
    that use `pass` or `continue` (do not re-raise)."""
    with open(filepath) as f:
        lines = f.readlines()

    new_lines = []
    modified = False
    i = 0
    while i < len(lines):
        line = lines[i]
        # Match lines like "    except Exception:" or "    except Exception as e:"
        m = re.match(r'^(\s*)except\s+Exception(\s+as\s+\w+)?:\s*$', line)
        if m:
            keyword_indent = m.group(1)
            body_indices = find_except_body(lines, i, keyword_indent)
            if body_indices:
                has_pc = body_has_pass_or_continue(lines, body_indices)
                has_r = body_has_raise(lines, body_indices)

                if has_pc and not has_r:
                    # Need to add CancelledError guard before this except clause
                    # Use the same indent level as the except keyword
                    new_lines.append(f'{keyword_indent}except asyncio.CancelledError:\n{keyword_indent}    raise\n')
                    new_lines.append(line)
                    modified = True
                    i += 1
                    continue

        new_lines.append(line)
        i += 1

    if modified:
        with open(filepath, 'w') as f:
            f.writelines(new_lines)
        count = sum(1 for l in new_lines if 'except asyncio.CancelledError' in l)
        print(f"  {filepath.name}: {count} CancelledError guard(s) added")
    return modified


def fix_log_calls() -> None:
    """Fix log() call signatures in ai_triage.py and ai_exploit.py."""
    base = Path('vulnforge')
    fixes = {
        'ai_triage.py': [
            ('log("AI Triage: loading findings...")',
             'log("info", "AI Triage: loading findings...")'),
            ('log("AI Triage: generating executive summary...")',
             'log("info", "AI Triage: generating executive summary...")'),
            ('log("  Written: ai_triage.json, ai_fps.json, ai_summary.txt")',
             'log("info", "  Written: ai_triage.json, ai_fps.json, ai_summary.txt")'),
        ],
        'ai_exploit.py': [
            ('log("AI Exploit: loading findings by phase...")',
             'log("info", "AI Exploit: loading findings by phase...")'),
            ('log("AI Exploit: requesting chain analysis from LLM...")',
             'log("info", "AI Exploit: requesting chain analysis from LLM...")'),
        ],
    }

    for fname, replacements in fixes.items():
        fp = base / fname
        if not fp.exists():
            print(f"  {fname}: not found")
            continue
        content = fp.read_text()
        for old, new in replacements:
            if old in content:
                content = content.replace(old, new)
                print(f"  {fname}: fixed log() call: {old[:50]}...")
        fp.write_text(content)


def fix_harvest() -> None:
    """Add return None to _probe_one in harvest.py."""
    fp = Path('vulnforge/phases/recon/harvest.py')
    if not fp.exists():
        return
    content = fp.read_text()
    lines = content.split('\n')

    # Find _probe_one function and add return None at the end
    new_lines = []
    in_probe_one = False
    probe_indent = None
    has_return_none = False
    modified = False

    for i, line in enumerate(lines):
        m = re.match(r'^(\s*)async def _probe_one\(', line)
        if m:
            in_probe_one = True
            probe_indent = m.group(1)
            new_lines.append(line)
            continue

        if in_probe_one:
            # Check if we've left the function body
            if line.strip() and not line.startswith(probe_indent + '    '):
                # We've exited the function - add return None before this line
                # First check if the last body line was already `return None`
                if not has_return_none:
                    new_lines.append(f'{probe_indent}    return None')
                    modified = True
                in_probe_one = False
                new_lines.append(line)
                continue

            # Check if this line has `return None`
            if 'return None' in line.strip():
                has_return_none = True

        new_lines.append(line)

    # If the function was the last thing in the file
    if in_probe_one and not has_return_none:
        new_lines.append(f'{probe_indent}    return None')
        modified = True

    if modified:
        fp.write_text('\n'.join(new_lines))
        print(f"  harvest.py: added return None to _probe_one")


def fix_credentials() -> None:
    """Rename InvalidToken → InvalidTokenError."""
    fp = Path('vulnforge/credentials.py')
    content = fp.read_text()

    # Change the import and fallback
    content = content.replace(
        'from cryptography.fernet import Fernet, InvalidToken',
        'from cryptography.fernet import Fernet, InvalidToken as InvalidTokenError'
    )
    content = content.replace(
        '    InvalidToken = Exception',
        '    InvalidTokenError = Exception'
    )
    # Update the except clause
    content = content.replace(
        'except InvalidToken:',
        'except InvalidTokenError:'
    )
    fp.write_text(content)
    print(f"  credentials.py: InvalidToken → InvalidTokenError")


def fix_process() -> None:
    """Add # type: ignore[no-redef] to tqdm fallback class."""
    fp = Path('vulnforge/process.py')
    content = fp.read_text()
    content = content.replace(
        '    class tqdm:',
        '    class tqdm:  # type: ignore[no-redef]'
    )
    fp.write_text(content)
    print(f"  process.py: added type: ignore[no-redef] to tqdm fallback")


if __name__ == '__main__':
    print("=== Bug Fixes ===\n")

    print("1. CancelledError guards in phase files...")
    phase_dir = Path('vulnforge/phases')
    for fname in ['helpers.py', 'vuln_scan.py', 'origin_cloud.py', 'smuggling.py',
                   'injection.py', 'injection_misc.py', 'auth.py', 'client_side.py',
                   'fuzzing.py', 'secrets_git.py', 'web_infra.py']:
        fp = phase_dir / fname
        if fp.exists():
            fix_cancelled_error(fp)

    print("\n2. Log call signatures...")
    fix_log_calls()

    print("\n3. harvest.py _probe_one return None...")
    fix_harvest()

    print("\n4. credentials.py InvalidToken...")
    fix_credentials()

    print("\n5. process.py tqdm type ignore...")
    fix_process()

    print("\n=== All fixes applied ===")
