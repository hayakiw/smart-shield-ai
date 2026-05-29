from __future__ import annotations

import asyncio
import logging
import os
import platform
import shutil

log = logging.getLogger("shield.banner")


class Banner:
    """Apply / remove platform-specific firewall blocks.

    Strategy:
      - Windows: netsh advfirewall firewall add/delete rule name="smart-shield-<ip>"
      - Linux:   iptables -I INPUT -s <ip> -j DROP   /   -D INPUT -s <ip> -j DROP
      - dry_run: only log; never invoke the OS.

    Concurrency:
      block/unblock/reapply は IP 単位の asyncio.Lock で直列化する。
      これによって以下のレースを防ぐ:
        1) unban_loop の unblock 中に jail/AI が同じ IP を再 ban → 古い -D が
           新しい -I の rule を削除してしまう物理レイヤのレース。
        2) 2 つの jail がほぼ同時に同じ IP を ban → iptables -I が 2 回走り
           DROP rule が重複して残る (後の unblock で 1 件しか消えずゾンビ化)。
    """

    RULE_PREFIX = "smart-shield-"

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.platform = platform.system().lower()
        self._locks: dict[str, asyncio.Lock] = {}
        # PATH に依存しないよう起動時に絶対パスを解決する。
        # 見つからない場合はそのままコマンド名を残す (dry_run なら呼ばれない)。
        self._iptables = (
            shutil.which("iptables")
            or ("/usr/sbin/iptables" if os.path.exists("/usr/sbin/iptables") else None)
            or ("/sbin/iptables" if os.path.exists("/sbin/iptables") else None)
            or "iptables"
        )
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        netsh_candidate = os.path.join(sysroot, "System32", "netsh.exe")
        self._netsh = (
            shutil.which("netsh")
            or (netsh_candidate if os.path.exists(netsh_candidate) else None)
            or "netsh"
        )

    def _lock_for(self, ip: str) -> asyncio.Lock:
        lock = self._locks.get(ip)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[ip] = lock
        return lock

    def gc_locks(self) -> int:
        """idle な Lock を一括削除する (dict 肥大化対策)。

        asyncio はシングルスレッドなので、await を挟まずに locked() を見て
        del する限りレースは起きない。次に同じ IP で block/unblock したら
        _lock_for が新しい Lock を作るが、その時点で誰も古い Lock を持って
        いないので正しく直列化できる。
        """
        stale = [ip for ip, lock in self._locks.items() if not lock.locked()]
        for ip in stale:
            del self._locks[ip]
        return len(stale)

    async def block(self, ip: str) -> bool:
        async with self._lock_for(ip):
            return await self._block_locked(ip)

    async def _block_locked(self, ip: str) -> bool:
        if self.dry_run:
            log.info("[dry-run] would block %s", ip)
            return True
        if self.platform == "windows":
            return await self._run(
                self._netsh, "advfirewall", "firewall", "add", "rule",
                f"name={self.RULE_PREFIX}{ip}",
                "dir=in", "action=block", f"remoteip={ip}",
            )
        if self.platform == "linux":
            return await self._run(self._iptables, "-I", "INPUT", "-s", ip, "-j", "DROP")
        log.warning("unsupported platform %s; cannot block %s", self.platform, ip)
        return False

    async def unblock(self, ip: str) -> bool:
        async with self._lock_for(ip):
            return await self._unblock_locked(ip)

    async def _unblock_locked(self, ip: str) -> bool:
        if self.dry_run:
            log.info("[dry-run] would unblock %s", ip)
            return True
        if self.platform == "windows":
            return await self._run(
                self._netsh, "advfirewall", "firewall", "delete", "rule",
                f"name={self.RULE_PREFIX}{ip}",
            )
        if self.platform == "linux":
            return await self._run(self._iptables, "-D", "INPUT", "-s", ip, "-j", "DROP")
        return False

    async def reapply(self, ip: str) -> bool:
        """起動時の再登録用に冪等に block する。

        iptables -I は同じ rule を重複して許容するため、再起動のたびに
        DROP rule が累積する。先に既存 rule を削除 (なくても無害なので失敗
        は無視) してから挿入することで、結果として常に 1 件だけになる。
        Windows netsh の add も同名 rule を許容するので同様に処理する。
        """
        async with self._lock_for(ip):
            if self.dry_run:
                log.info("[dry-run] would reapply block for %s", ip)
                return True
            if self.platform == "windows":
                await self._run_quiet(
                    self._netsh, "advfirewall", "firewall", "delete", "rule",
                    f"name={self.RULE_PREFIX}{ip}",
                )
            elif self.platform == "linux":
                # 重複した rule が複数残っている可能性に備えてループで全部消す
                for _ in range(8):
                    ok = await self._run_quiet(
                        self._iptables, "-D", "INPUT", "-s", ip, "-j", "DROP",
                    )
                    if not ok:
                        break
            return await self._block_locked(ip)

    async def _run(self, *cmd: str) -> bool:
        log.debug("exec: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        ok = proc.returncode == 0
        if not ok:
            log.error(
                "command failed (%s): %s | stderr=%s",
                proc.returncode, " ".join(cmd), stderr.decode("utf-8", "replace").strip(),
            )
        return ok

    async def _run_quiet(self, *cmd: str) -> bool:
        """失敗を期待しうるコマンド用 (削除を試行 → 存在しないので 1 が返る等)。
        失敗してもログレベルを debug に抑える。"""
        log.debug("exec (quiet): %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        return proc.returncode == 0
