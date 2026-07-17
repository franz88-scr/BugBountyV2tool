"""Distributed scanning via SSH for multi-host parallelism."""
from __future__ import annotations
import asyncio
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from reconchain.utils import log, ensure


class SSHScanner:
    """Distribute scan tasks across remote hosts via SSH."""
    
    def __init__(self, hosts: List[str], max_workers: int = 5, 
                 ssh_key: str = "", ssh_user: str = "root"):
        self.hosts = hosts
        self.max_workers = min(max_workers, len(hosts))
        self.ssh_key = ssh_key
        self.ssh_user = ssh_user
        self.worker_hosts: List[str] = []
    
    async def _run_on_host(self, host: str, command: str, 
                          timeout: int = 300) -> Dict[str, Any]:
        """Run a command on a remote host via SSH."""
        ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new"]
        if self.ssh_key:
            ssh_cmd.extend(["-i", self.ssh_key])
        ssh_cmd.extend([f"{self.ssh_user}@{host}", shlex.quote(command)]
        )
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return {
                "host": host,
                "returncode": proc.returncode,
                "stdout": stdout.decode("utf-8", errors="ignore"),
                "stderr": stderr.decode("utf-8", errors="ignore"),
            }
        except asyncio.TimeoutError:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return {
                "host": host,
                "returncode": -1,
                "stdout": "",
                "stderr": "timeout",
            }
        except asyncio.CancelledError:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            raise
        except Exception as e:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return {
                "host": host,
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
            }
    
    async def distribute_tasks(self, tasks: List[str], 
                              outdir: Path) -> List[Dict[str, Any]]:
        """Distribute tasks across available hosts."""
        if not self.hosts:
            log("warn", "No remote hosts configured for distributed scanning")
            return []
        
        # Round-robin task distribution
        results = []
        sem = asyncio.Semaphore(self.max_workers)
        
        async def worker(host: str, task: str):
            async with sem:
                result = await self._run_on_host(host, task)
                results.append(result)
        
        # Create worker tasks
        worker_tasks = []
        for i, task in enumerate(tasks):
            host = self.hosts[i % len(self.hosts)]
            worker_tasks.append(worker(host, task))
        
        await asyncio.gather(*worker_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                log("err", f"distributed worker failed: {r}")
        
        # Aggregate results
        out = ensure(outdir / "distributed_results.json")
        out.write_text(json.dumps(results, indent=2, default=str))
        log("ok", f"Distributed scan: {len(results)} results → {out}")
        return results
    
    def setup_workers(self) -> None:
        """Setup worker connections to remote hosts."""
        log("info", f"Setting up {len(self.hosts)} remote workers")
        # Verify SSH connectivity
        for host in self.hosts:
            log("info", f"  - {host}")


def create_scanner_from_config(config: Dict[str, Any]) -> Optional[SSHScanner]:
    """Create SSHScanner from configuration dictionary."""
    hosts = config.get("distributed_hosts", [])
    if not hosts:
        return None
    
    return SSHScanner(
        hosts=hosts,
        max_workers=config.get("distributed_workers", 5),
        ssh_key=config.get("distributed_ssh_key", ""),
        ssh_user=config.get("distributed_ssh_user", "root"),
    )
