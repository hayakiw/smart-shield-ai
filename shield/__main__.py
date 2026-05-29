from __future__ import annotations

import argparse
import asyncio
import logging
import os
import platform
import signal
import socket
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from .ai_analyzer import AIAnalyzer
from .banner import Banner
from .config import ShieldConfig, is_valid_ip, load_config
from .filters import Filter
from .jail import Jail
from .monitor import LogTailer
from .store import Store

log = logging.getLogger("shield")


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _process_alive(pid: int) -> bool:
    """PID が生きているプロセスを指しているか。

    POSIX は kill(pid, 0) で OK。Windows は os.kill(pid, 0) が生死を正しく
    区別できない (権限なしと死亡が両方 OSError になる) ため、Win32 API の
    OpenProcess + GetExitCodeProcess を直接呼んで判定する。
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if not handle:
            return False
        try:
            exit_code = wintypes.DWORD()
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            if not ok:
                return False
            return exit_code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # 別ユーザのプロセスがその PID を持っている → 生きている
        return True
    except OSError:
        return False
    return True


@contextmanager
def _pid_file(path: Path):
    """Best-effort PID file. The OS service manager is the real arbiter of
    single-instance — this just leaves a breadcrumb for operators.

    O_CREAT|O_EXCL で atomic に作る (前回の単純な exists/write には TOCTOU
    があった)。既存ファイルが死んだ PID を指しているならステールとして
    上書き、生きていれば WARNING を出して上書きを試みる (運用ポリシー上
    停止までは行わない)。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        fd = os.open(str(path), flags, 0o644)
    except FileExistsError:
        try:
            old = int(path.read_text().strip() or "0")
        except (ValueError, OSError):
            old = 0
        if _process_alive(old):
            log.warning(
                "pid file %s already held by live pid=%d — overwriting anyway",
                path, old,
            )
        else:
            log.warning("stale pid file at %s (pid=%s) — replacing", path, old)
        try:
            path.unlink()
        except OSError:
            pass
        try:
            fd = os.open(str(path), flags, 0o644)
        except OSError as e:
            log.error("could not create pid file at %s: %s", path, e)
            fd = -1
    if fd >= 0:
        with os.fdopen(fd, "w") as f:
            f.write(str(os.getpid()))
    try:
        yield
    finally:
        try:
            if path.exists() and path.read_text().strip() == str(os.getpid()):
                path.unlink()
        except OSError:
            pass


async def _safe_run(
    coro_fn, name: str, restart_delay: float = 5.0
) -> None:
    """1 worker が例外で死んでも daemon 全体を止めないための supervisor。

    Cancel は伝播 (graceful shutdown のため)。それ以外の Exception は
    ログを残して restart_delay 秒待ってから coro_fn を再起動する。

    coro_fn が正常 return した場合 (例: AI が API キー未設定で run_forever
    が即 return) は cancel まで idle で待つ。これで asyncio.wait の
    FIRST_COMPLETED が誤って shutdown を引き起こさない。
    """
    while True:
        try:
            await coro_fn()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("%s crashed; restarting in %.1fs", name, restart_delay)
            try:
                await asyncio.sleep(restart_delay)
            except asyncio.CancelledError:
                raise
            continue
        # 正常 return: もう仕事は無いが、他の worker と並列に走り続ける
        # 前提なので、ここで return すると asyncio.wait(FIRST_COMPLETED) が
        # 全体 shutdown を引き起こす。cancel が来るまで idle で待つ。
        log.info("%s completed normally; idling until stop", name)
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            raise


async def _tail_into_jails(
    path: str,
    jails: list[Jail],
    ai: AIAnalyzer | None,
    store: Store,
) -> None:
    tailer = LogTailer(path, store)
    async for line in tailer.lines():
        if ai is not None:
            try:
                ai.ingest(path, line)
            except Exception:
                # buffer 操作の予期せぬ例外 (メモリ不足など) で tail を止めない
                log.exception("ai.ingest failed for %s", path)
        for jail in jails:
            try:
                await jail.process_line(line)
            except Exception:
                # 1 つの jail の処理失敗で tail 全体を止めない
                log.exception("jail %s failed on line: %r", jail.cfg.name, line[:200])


async def _unban_loop(
    store: Store,
    banner: Banner,
    unblock_retry: dict[tuple[str, int], int],
    interval: int = 30,
) -> None:
    # retry 辞書は呼び出し元 (_safe_run の外側) で確保された永続 state を
    # 共有する。_safe_run でループが再起動しても retry カウントが失われない。
    # MAX_RETRIES に達したら諦めて DB を強制 deactivate する (firewall に
    # rule が無くなってしまった等で永久 retry になるのを防ぐ)。
    MAX_RETRIES = 3
    while True:
        now = int(time.time())
        for rec in store.list_expired(now):
            key = (rec.ip, rec.banned_at)
            ok = await banner.unblock(rec.ip)
            if ok:
                # await 中に同じ IP が再 ban された場合、新しい行は banned_at が
                # 違うので deactivate されない (= 新規 ban を巻き添えで消さない)。
                store.deactivate_ban(rec.ip, banned_at=rec.banned_at)
                store.log_event(
                    "unban",
                    ip=rec.ip,
                    detail=f"source={rec.source}; jail={rec.jail}",
                )
                log.info(
                    "UNBAN ip=%s (was source=%s jail=%s)",
                    rec.ip, rec.source, rec.jail,
                )
                unblock_retry.pop(key, None)
            else:
                count = unblock_retry.get(key, 0) + 1
                unblock_retry[key] = count
                if count >= MAX_RETRIES:
                    log.warning(
                        "unblock failed %d times for %s; force-deactivating DB record",
                        count, rec.ip,
                    )
                    store.deactivate_ban(rec.ip, banned_at=rec.banned_at)
                    store.log_event(
                        "unban-failed",
                        ip=rec.ip,
                        detail=f"gave up after {count} retries",
                    )
                    unblock_retry.pop(key, None)
                else:
                    log.debug(
                        "unblock failed for %s (%d/%d); will retry next loop",
                        rec.ip, count, MAX_RETRIES,
                    )
        await asyncio.sleep(interval)


async def _gc_loop(
    store: Store, banner: Banner, cfg: ShieldConfig, interval: int = 3600
) -> None:
    while True:
        now = int(time.time())
        # attempts: 最大 findtime の 4 倍残せば十分
        max_window = max((j.findtime_seconds for j in cfg.jails.values()), default=3600)
        cutoff_attempts = now - max_window * 4
        removed_a = store.gc_attempts(cutoff_attempts)

        # events: count_bans_since が参照するため、recidive の lookback より
        # 古いものだけを刈る。recidive 無効時は 30 日を保持上限にする。
        if cfg.global_.recidive.enabled:
            keep_events = cfg.global_.recidive.lookback_seconds * 2
        else:
            keep_events = 30 * 24 * 3600
        removed_e = store.gc_events(now - keep_events)

        # 解放可能な DB ページを実 size に還元 (auto_vacuum=INCREMENTAL 前提)
        store.incremental_vacuum()

        # 使われていない IP Lock を回収 (長期運用で _locks が肥大しないよう)
        removed_l = banner.gc_locks()

        if removed_a or removed_e or removed_l:
            log.debug(
                "gc: pruned %d attempts, %d events, %d idle locks",
                removed_a, removed_e, removed_l,
            )
        await asyncio.sleep(interval)


async def _reapply_active_bans(
    store: Store, banner: Banner, stop_event: asyncio.Event | None = None
) -> None:
    """OS のファイアウォール (iptables / netsh) は再起動で消えるため、
    SQLite に残っている active な ban を起動時に再登録する。
    dry_run の間は banner 側で no-op になる。

    - DB 上の ip が IP として妥当でなければ skip + WARN (旧バージョンや
      CLI 誤入力で混入した無効値で firewall を叩かないためのガード)。
    - banner.reapply は内部で既存 rule を削除してから挿入するので、
      再起動を繰り返しても DROP rule が累積しない。
    - 大量 ban で reapply が長時間化したケースで Ctrl-C / SIGTERM が
      来たら、ループを抜けて shutdown シーケンスに進む。
    """
    active = store.list_active()
    if not active:
        return
    log.info("re-applying %d active bans to OS firewall", len(active))
    reapplied = 0
    skipped = 0
    interrupted = False
    for rec in active:
        if stop_event is not None and stop_event.is_set():
            log.info("re-apply interrupted by stop signal")
            interrupted = True
            break
        if not is_valid_ip(rec.ip):
            log.warning("skip reapply of invalid ip in DB: %r", rec.ip)
            skipped += 1
            continue
        ok = await banner.reapply(rec.ip)
        if ok:
            reapplied += 1
        else:
            log.warning("could not re-apply ban for %s", rec.ip)
    store.log_event(
        "reapply",
        detail=(
            f"reapplied={reapplied}/{len(active)} skipped={skipped}"
            + (" interrupted=1" if interrupted else "")
        ),
    )
    log.info(
        "re-apply complete: %d/%d (skipped %d invalid%s)",
        reapplied, len(active), skipped,
        ", interrupted" if interrupted else "",
    )


def _build_jail_index(cfg: ShieldConfig, store: Store, banner: Banner) -> dict[str, list[Jail]]:
    """Map each watched path to the list of jails that should consume it."""
    by_path: dict[str, list[Jail]] = {}
    for jail_cfg in cfg.jails.values():
        if not jail_cfg.enabled:
            continue
        flt = Filter(cfg.filters[jail_cfg.filter])
        jail = Jail(jail_cfg, flt, store, banner, cfg)
        for p in jail_cfg.paths:
            if not Path(p).exists():
                log.info("skip non-existent log path: %s", p)
                continue
            by_path.setdefault(p, []).append(jail)
    return by_path


async def _amain(args: argparse.Namespace) -> None:
    cfg = load_config(Path(args.config))
    _setup_logging(cfg.global_.log_level)

    store = Store(cfg.global_.state_db)
    banner = Banner(dry_run=cfg.global_.dry_run)

    try:
        await _dispatch(args, cfg, store, banner)
    finally:
        # status / unban / ban / run のどのパスでも、終了時に WAL を
        # checkpoint して接続を閉じる。
        store.close()


async def _dispatch(
    args: argparse.Namespace, cfg: ShieldConfig, store: Store, banner: Banner
) -> None:
    if args.subcommand == "status":
        _print_status(store)
        return
    if args.subcommand == "unban":
        await _cmd_unban(args.ip, store, banner)
        return
    if args.subcommand == "ban":
        await _cmd_ban(args.ip, args.seconds, args.reason, args.permanent, store, banner)
        return

    log.info(
        "smart-shield starting on %s [%s] (pid=%d, dry_run=%s, jails=%d, ai=%s)",
        socket.gethostname(),
        platform.platform(),
        os.getpid(),
        cfg.global_.dry_run,
        sum(1 for j in cfg.jails.values() if j.enabled),
        "on" if cfg.ai.enabled else "off",
    )

    ai = AIAnalyzer(cfg.ai, cfg, store, banner) if cfg.ai.enabled else None
    by_path = _build_jail_index(cfg, store, banner)

    # Add AI-only sources (paths watched solely for AI inspection)
    if ai is not None:
        for src in cfg.ai.sources:
            if Path(src).exists() and src not in by_path:
                by_path[src] = []

    if not by_path:
        log.warning("no log paths to watch — exiting")
        return

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _request_stop() -> None:
        loop.call_soon_threadsafe(stop_event.set)

    # signal handler の復元用に、上書き前の handler を保存しておく。
    # _amain 終了時に元へ戻して、process global state を汚さない。
    prior_handlers: list[tuple[int, object]] = []
    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            # Windows asyncio loops は add_signal_handler を SIGINT/SIGTERM 共に
            # サポートしない。標準 signal.signal で代替し、ハンドラから
            # call_soon_threadsafe で stop_event を set する。これで Ctrl-C や
            # NSSM の Stop で graceful shutdown が走る。
            try:
                prev = signal.getsignal(sig)
                signal.signal(sig, lambda *_: _request_stop())
                prior_handlers.append((sig, prev))
            except (ValueError, OSError):
                pass

    pid_path = cfg.global_.state_db.parent / "shield.pid"
    try:
        with _pid_file(pid_path):
            store.log_event("startup", detail=f"pid={os.getpid()} host={socket.gethostname()}")
            await _reapply_active_bans(store, banner, stop_event)
            if stop_event.is_set():
                log.info("stop requested during startup; exiting")
                store.log_event("shutdown", detail="aborted-during-startup")
                return
            tasks: list[asyncio.Task] = []
            for path, jails in by_path.items():
                tasks.append(asyncio.create_task(
                    _safe_run(
                        lambda p=path, js=jails: _tail_into_jails(p, js, ai, store),
                        name=f"tail:{path}",
                    ),
                    name=f"tail:{path}",
                ))
            # _safe_run の再起動で retry カウントが失われないよう、辞書を
            # ループの外側で確保して引き回す。
            unblock_retry: dict[tuple[str, int], int] = {}
            tasks.append(asyncio.create_task(
                _safe_run(
                    lambda: _unban_loop(store, banner, unblock_retry),
                    name="unban-loop",
                ),
                name="unban-loop",
            ))
            tasks.append(asyncio.create_task(
                _safe_run(lambda: _gc_loop(store, banner, cfg), name="gc-loop"),
                name="gc-loop",
            ))
            if ai is not None:
                tasks.append(asyncio.create_task(
                    _safe_run(ai.run_forever, name="ai-loop"),
                    name="ai-loop",
                ))

            stop_task = asyncio.create_task(stop_event.wait(), name="stop")
            await asyncio.wait([*tasks, stop_task], return_when=asyncio.FIRST_COMPLETED)
            log.info("shutting down...")
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            store.log_event("shutdown")
    finally:
        # signal handler を元に戻す (process global を汚さない)
        for sig, prev in prior_handlers:
            try:
                signal.signal(sig, prev)
            except (ValueError, OSError, TypeError):
                pass
        # store.close() は _amain の外側の finally で実行


def _print_status(store: Store) -> None:
    active = store.list_active()
    if not active:
        print("no active bans")
        return
    now = int(time.time())
    ip_w = max(len("IP"), max(len(b.ip) for b in active))
    jail_w = max(len("JAIL"), max(len(b.jail) for b in active))
    src_w = max(len("SRC"), max(len(b.source) for b in active))
    print(f"{'IP':<{ip_w}} {'SRC':<{src_w}} {'JAIL':<{jail_w}} {'REMAIN':>10}  REASON")
    for b in active:
        remain_str = "permanent" if b.expires_at == 0 else f"{max(0, b.expires_at - now):>7}s"
        print(
            f"{b.ip:<{ip_w}} {b.source:<{src_w}} {b.jail:<{jail_w}} "
            f"{remain_str:>10}  {b.reason}"
        )


async def _cmd_unban(ip: str, store: Store, banner: Banner) -> None:
    if not is_valid_ip(ip):
        print(f"invalid ip: {ip!r}")
        return
    rec = store.get_active_ban(ip)
    if rec is None:
        print(f"no active ban for {ip}")
        return
    ok = await banner.unblock(ip)
    store.deactivate_ban(ip)
    store.log_event("unban-manual" if ok else "unban-failed", ip=ip)
    dry = " [dry-run: firewall unchanged]" if banner.dry_run else ""
    print(f"unbanned {ip} (firewall ok={ok}){dry}")


async def _cmd_ban(
    ip: str, seconds: int, reason: str, permanent: bool,
    store: Store, banner: Banner,
) -> None:
    if not is_valid_ip(ip):
        print(f"invalid ip: {ip!r}")
        return
    effective = 0 if permanent else seconds
    existing = store.get_active_ban(ip)
    if existing and existing.expires_at == 0 and effective > 0:
        # 永久 ban を一時 ban に格下げしないためのガード。
        # 意図的に格下げしたい場合は先に `unban` を実行する。
        print(
            f"{ip} is already permanently banned; "
            f"run `unban {ip}` first if you want to downgrade"
        )
        return
    store.add_ban(ip=ip, jail="manual", reason=reason or "manual", source="manual",
                  ban_seconds=effective)
    ok = await banner.block(ip)
    store.log_event("ban-manual" if ok else "ban-failed", ip=ip, detail=reason)
    label = "permanent" if effective <= 0 else f"{effective}s"
    dry = " [dry-run: firewall unchanged]" if banner.dry_run else ""
    print(f"banned {ip} ({label}, firewall ok={ok}){dry}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="smart-shield")
    parser.add_argument("-c", "--config", default="config/shield.yaml")
    sub = parser.add_subparsers(dest="subcommand")

    sub.add_parser("run", help="run the watcher (default)")
    sub.add_parser("status", help="print active bans")

    p_unban = sub.add_parser("unban", help="manually unban an ip")
    p_unban.add_argument("ip")

    p_ban = sub.add_parser("ban", help="manually ban an ip")
    p_ban.add_argument("ip")
    p_ban.add_argument("--seconds", type=int, default=3600,
                       help="ban duration in seconds (ignored if --permanent)")
    p_ban.add_argument("--permanent", action="store_true",
                       help="never auto-expire (must be unbanned manually)")
    p_ban.add_argument("--reason", default="manual")

    args = parser.parse_args()
    if args.subcommand is None:
        args.subcommand = "run"

    try:
        asyncio.run(_amain(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
