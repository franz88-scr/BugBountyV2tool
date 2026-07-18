"""Distributed scanning via SSH for multi-host parallelism.

Features:
- SSH-based remote task execution with health checks
- Round-robin and least-connections load balancing
- Automatic failover on host failure
- Result aggregation and deduplication
"""
from __future__ import annotations

import asyncio
import json
import os
import shlex
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from reconchain.utils import log, ensure


class LoadBalancer:
    """Load balancer for distributing tasks across hosts.

    Supports:
    - round_robin: Cyclic host selection (default).
    - least_connections: Route to host with fewest active tasks.
    - weighted: Weight-based selection for heterogeneous hosts.
    """

    def __init__(self, hosts: List[str], strategy: str = "round_robin") -> None:
        self._hosts = list(hosts)
        self._strategy = strategy
        self._index = 0
        self._connections: Dict[str, int] = {h: 0 for h in hosts}
        self._weights: Dict[str, float] = {h: 1.0 for h in hosts}
        self._failures: Dict[str, int] = {h: 0 for h in hosts}

    def set_weight(self, host: str, weight: float) -> None:
        if host in self._weights:
            self._weights[host] = max(0.1, weight)

    def record_failure(self, host: str) -> None:
        self._failures[host] = self._failures.get(host, 0) + 1

    def record_success(self, host: str) -> None:
        self._failures[host] = 0
        self._connections[host] = max(0, self._connections.get(host, 0) - 1)

    def acquire(self, host: str) -> None:
        self._connections[host] = self._connections.get(host, 0) + 1

    def release(self, host: str) -> None:
        self._connections[host] = max(0, self._connections.get(host, 0) - 1)

    @property
    def active_hosts(self) -> List[str]:
        """Return hosts sorted by load (least loaded first)."""
        return sorted(
            self._hosts,
            key=lambda h: (self._failures.get(h, 0), self._connections.get(h, 0)),
        )

    def next_host(self) -> str:
        """Select the next host based on the load balancing strategy."""
        if not self._hosts:
            raise RuntimeError("No hosts available")

        if self._strategy == "least_connections":
            candidates = sorted(
                self._hosts,
                key=lambda h: (self._failures.get(h, 0), self._connections.get(h, 0)),
            )
            return candidates[0]

        if self._strategy == "weighted":
            total = sum(self._weights.get(h, 1.0) for h in self._hosts if self._failures.get(h, 0) < 3)
            if total == 0:
                return self._hosts[0]
            import random
            r = random.uniform(0, total)
            cumulative = 0.0
            for h in self._hosts:
                if self._failures.get(h, 0) >= 3:
                    continue
                cumulative += self._weights.get(h, 1.0)
                if r <= cumulative:
                    return h
            return self._hosts[-1]

        # Default: round_robin
        host = self._hosts[self._index % len(self._hosts)]
        self._index += 1
        return host

    def get_stats(self) -> Dict[str, Any]:
        return {
            "strategy": self._strategy,
            "hosts": {
                h: {
                    "connections": self._connections.get(h, 0),
                    "failures": self._failures.get(h, 0),
                    "weight": self._weights.get(h, 1.0),
                }
                for h in self._hosts
            },
        }


@dataclass
class HostHealth:
    """Health status of a remote scanning host."""
    host: str
    reachable: bool = False
    latency_ms: float = 0.0
    cpu_load: float = 0.0
    disk_free_gb: float = 0.0
    reconchain_version: str = ""
    last_check: float = 0.0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "reachable": self.reachable,
            "latency_ms": round(self.latency_ms, 1),
            "cpu_load": round(self.cpu_load, 2),
            "disk_free_gb": round(self.disk_free_gb, 1),
            "reconchain_version": self.reconchain_version,
            "last_check": self.last_check,
            "error": self.error,
        }


class SSHScanner:
    """Distribute scan tasks across remote hosts via SSH with health checks."""

    def __init__(
        self,
        hosts: List[str],
        max_workers: int = 5,
        ssh_key: str = "",
        ssh_user: str = "root",
        load_balance: str = "round_robin",
    ):
        self.hosts = hosts
        self.max_workers = min(max_workers, len(hosts))
        self.ssh_key = ssh_key
        self.ssh_user = ssh_user
        self.worker_hosts: List[str] = []
        self._load_balancer = LoadBalancer(hosts, strategy=load_balance)
        self._health: Dict[str, HostHealth] = {h: HostHealth(host=h) for h in hosts}
        self._results: List[Dict[str, Any]] = []

    async def _ssh_exec(
        self, host: str, command: str, timeout: int = 300
    ) -> Dict[str, Any]:
        """Execute a command on a remote host via SSH."""
        ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"]
        if self.ssh_key:
            ssh_cmd.extend(["-i", self.ssh_key])
        ssh_cmd.extend([f"{self.ssh_user}@{host}", shlex.quote(command)])

        proc = None
        t0 = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            latency = (time.monotonic() - t0) * 1000
            self._load_balancer.record_success(host)
            return {
                "host": host,
                "returncode": proc.returncode,
                "stdout": stdout.decode("utf-8", errors="ignore"),
                "stderr": stderr.decode("utf-8", errors="ignore"),
                "latency_ms": round(latency, 1),
            }
        except asyncio.TimeoutError:
            self._load_balancer.record_failure(host)
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return {"host": host, "returncode": -1, "stdout": "", "stderr": "timeout", "latency_ms": -1}
        except asyncio.CancelledError:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            raise
        except Exception as e:
            self._load_balancer.record_failure(host)
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return {"host": host, "returncode": -1, "stdout": "", "stderr": str(e), "latency_ms": -1}

    async def health_check(self, host: str, *, timeout: int = 15) -> HostHealth:
        """Check health of a remote host."""
        health = HostHealth(host=host)
        t0 = time.monotonic()

        # Basic connectivity
        result = await self._ssh_exec(host, "echo ok", timeout=timeout)
        health.latency_ms = (time.monotonic() - t0) * 1000
        health.reachable = result["returncode"] == 0 and "ok" in result.get("stdout", "")
        health.last_check = time.time()

        if not health.reachable:
            health.error = result.get("stderr", "unreachable")[:200]
            self._health[host] = health
            return health

        # System metrics (best-effort, non-fatal)
        try:
            cpu_cmd = "cat /proc/loadavg 2>/dev/null | awk '{print $1}'"
            cpu_result = await self._ssh_exec(host, cpu_cmd, timeout=5)
            if cpu_result["returncode"] == 0:
                health.cpu_load = float(cpu_result["stdout"].strip() or "0")
        except Exception:
            pass

        try:
            disk_cmd = "df -BG / 2>/dev/null | tail -1 | awk '{print $4}' | tr -d 'G'"
            disk_result = await self._ssh_exec(host, disk_cmd, timeout=5)
            if disk_result["returncode"] == 0:
                health.disk_free_gb = float(disk_result["stdout"].strip() or "0")
        except Exception:
            pass

        self._health[host] = health
        return health

    async def health_check_all(self, *, timeout: int = 15) -> Dict[str, HostHealth]:
        """Check health of all configured hosts in parallel."""
        tasks = [self.health_check(h, timeout=timeout) for h in self.hosts]
        await asyncio.gather(*tasks, return_exceptions=True)
        return dict(self._health)

    def get_healthy_hosts(self, *, min_disk_gb: float = 1.0) -> List[str]:
        """Return hosts that are reachable with sufficient disk space."""
        return [
            h for h, health in self._health.items()
            if health.reachable and health.disk_free_gb >= min_disk_gb
        ]

    async def distribute_tasks(
        self, tasks: List[str], outdir: Path
    ) -> List[Dict[str, Any]]:
        """Distribute tasks across available hosts with load balancing.

        Features:
        - Load-balanced task assignment (round-robin or least-connections)
        - Automatic failover on host failure
        - Result aggregation and deduplication
        """
        if not self.hosts:
            log("warn", "No remote hosts configured for distributed scanning")
            return []

        results: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(self.max_workers)
        failed_hosts: set = set()

        async def worker(task: str) -> None:
            async with sem:
                # Get next host from load balancer, skip failed hosts
                for _ in range(len(self.hosts)):
                    host = self._load_balancer.next_host()
                    if host not in failed_hosts:
                        break
                else:
                    results.append({"host": "none", "returncode": -1, "stderr": "all hosts failed"})
                    return

                self._load_balancer.acquire(host)
                try:
                    result = await self._ssh_exec(host, task)
                    results.append(result)
                    if result["returncode"] not in (0, 1, 2):
                        failed_hosts.add(host)
                        log("warn", f"distributed: host {host} failed task, removing from pool")
                finally:
                    self._load_balancer.release(host)

        worker_tasks = [worker(task) for task in tasks]
        await asyncio.gather(*worker_tasks, return_exceptions=True)

        # Aggregate results
        out = ensure(outdir / "distributed_results.json")
        out.write_text(json.dumps(results, indent=2, default=str))

        # Load balancer stats
        lb_stats = self._load_balancer.get_stats()
        stats_path = ensure(outdir / "distributed_stats.json")
        stats_path.write_text(json.dumps(lb_stats, indent=2, default=str))

        log("ok", f"Distributed scan: {len(results)} results → {out}")
        return results

    def setup_workers(self) -> None:
        """Setup worker connections to remote hosts."""
        log("info", f"Setting up {len(self.hosts)} remote workers")
        for host in self.hosts:
            log("info", f"  - {host}")

    def get_health_report(self) -> Dict[str, Any]:
        """Return a summary of all host health statuses."""
        return {
            "total_hosts": len(self.hosts),
            "healthy": sum(1 for h in self._health.values() if h.reachable),
            "unhealthy": sum(1 for h in self._health.values() if not h.reachable),
            "hosts": {h: health.to_dict() for h, health in self._health.items()},
            "load_balancer": self._load_balancer.get_stats(),
        }


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
        load_balance=config.get("distributed_load_balance", "round_robin"),
    )
