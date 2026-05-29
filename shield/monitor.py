from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import AsyncIterator
from pathlib import Path

from .store import Store

log = logging.getLogger("shield.monitor")


class LogTailer:
    """Resumable, rotation-aware async tail for a single log file.

    Uses inode (on POSIX) or ctime (on Windows where stat.st_ino is 0) to
    detect rotation. Position is persisted to the store so restarts pick up
    where they left off.

    File handle はループ間で保持する。これによりローテーションを検知した時、
    まだ生きている旧 handle で末尾まで読み切ってから新ファイルに切り替えら
    れる (poll 間隔中に書き込まれた最後の数行を取りこぼさない)。
    """

    def __init__(self, path: str, store: Store, poll_interval: float = 0.5):
        self.path = path
        self.store = store
        self.poll_interval = poll_interval

    @staticmethod
    def _inode_key(st: os.stat_result) -> str:
        if st.st_ino:
            return f"ino:{st.st_ino}"
        # Windows fallback: st_size を含めると追記のたびにキーが変わって
        # ローテーションと誤検出するので、生成時刻のみで識別する。
        return f"win:{st.st_ctime_ns}"

    def _drain(self, fh, last_offset: int, yield_partial: bool = False):
        """fh から読める分を yield 用のリストに溜める内部ヘルパ。

        (lines_to_yield, new_offset) を返す。
        - 通常: 部分行 (改行未到達) は次回のために巻き戻して残す。
        - yield_partial=True: rotation 直前など「この handle はもう読めない」
          ケース。改行未到達の最終行も出力に含める (取りこぼし回避)。
        """
        out: list[str] = []
        while True:
            line = fh.readline()
            if not line:
                last_offset = fh.tell()
                break
            if line.endswith("\n"):
                out.append(line.rstrip("\n").rstrip("\r"))
                last_offset = fh.tell()
            else:
                if yield_partial:
                    # ローテーション時の最終ドレイン: 改行が来ないまま消える
                    # 行を救出 (新ファイル側からはもう読めない)
                    out.append(line.rstrip("\r"))
                    last_offset = fh.tell()
                else:
                    # 部分行: 次回完全に読み込めるよう offset を巻き戻す
                    fh.seek(last_offset)
                break
        return out, last_offset

    async def lines(self) -> AsyncIterator[str]:
        p = Path(self.path)
        last_offset, last_inode = self.store.get_file_position(self.path)
        fh = None

        def _drop_handle():
            nonlocal fh
            if fh is not None:
                try:
                    fh.close()
                except OSError:
                    pass
                fh = None

        try:
            while True:
                # 1) 必要なら新たに open
                if fh is None:
                    if not p.exists():
                        await asyncio.sleep(self.poll_interval)
                        continue
                    try:
                        fh = p.open("r", encoding="utf-8", errors="replace")
                        st = os.fstat(fh.fileno())
                    except FileNotFoundError:
                        _drop_handle()
                        await asyncio.sleep(self.poll_interval)
                        continue
                    except (PermissionError, OSError) as e:
                        # 権限拒否や NFS 障害など。ループを死なせずリトライ。
                        log.warning("tail open/stat failed for %s: %s", self.path, e)
                        _drop_handle()
                        await asyncio.sleep(self.poll_interval)
                        continue
                    cur_inode = self._inode_key(st)
                    if last_inode is None or cur_inode == last_inode:
                        # 同一ファイル: 前回の続きから
                        try:
                            fh.seek(last_offset)
                        except OSError as e:
                            log.warning("seek failed on %s: %s", self.path, e)
                            _drop_handle()
                            await asyncio.sleep(self.poll_interval)
                            continue
                    else:
                        # 起動時点で既に rotation 済み: 旧ファイルにはもう
                        # アクセスできないので新ファイル先頭から
                        log.info("rotation detected at re-open: %s", self.path)
                        last_offset = 0
                    last_inode = cur_inode

                # 2) 現 handle から読める分を全部出す
                try:
                    batch, last_offset = self._drain(fh, last_offset)
                except OSError as e:
                    log.warning("read failed on %s: %s — reopening", self.path, e)
                    _drop_handle()
                    await asyncio.sleep(self.poll_interval)
                    continue
                for line in batch:
                    yield line
                try:
                    self.store.set_file_position(self.path, last_offset, last_inode)
                except Exception:
                    # DB 一時障害でも tail は続ける
                    log.exception("persist offset failed for %s", self.path)

                # 3) disk 側でローテーション / truncation が起きていないか確認
                try:
                    disk_st = p.stat()
                except FileNotFoundError:
                    # 一時的にファイルが消えている (rotation 中など) — handle
                    # を閉じて次 poll で再 open を試みる
                    _drop_handle()
                    await asyncio.sleep(self.poll_interval)
                    continue
                except OSError as e:
                    log.warning("stat failed on %s: %s", self.path, e)
                    _drop_handle()
                    await asyncio.sleep(self.poll_interval)
                    continue

                disk_inode = self._inode_key(disk_st)
                if disk_inode != last_inode:
                    # ローテーション検知: 旧 handle で末尾まで読み切ってから
                    # close する。これで poll 間隔中に書かれた最後の数行を
                    # 取りこぼさない。
                    log.info("rotation detected: %s", self.path)
                    try:
                        tail, _ = self._drain(fh, last_offset, yield_partial=True)
                    except OSError as e:
                        log.warning("final drain failed on %s: %s", self.path, e)
                        tail = []
                    for line in tail:
                        yield line
                    _drop_handle()
                    last_offset = 0
                    last_inode = disk_inode
                    self.store.set_file_position(self.path, 0, last_inode)
                    continue
                elif disk_st.st_size < last_offset:
                    # truncation: 同一 inode で size が縮んだ
                    log.info("truncation detected: %s", self.path)
                    _drop_handle()
                    last_offset = 0
                    self.store.set_file_position(self.path, 0, last_inode)
                    continue

                await asyncio.sleep(self.poll_interval)
        finally:
            _drop_handle()
