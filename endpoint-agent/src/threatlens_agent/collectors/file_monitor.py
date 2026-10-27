"""Linux file-system telemetry collector using non-blocking inotify.

Observes file_created, file_modified, file_renamed, and file_deleted events
within explicitly configured directories. Strictly non-destructive, opt-in,
and bounds-checked.
"""

from __future__ import annotations

import collections
import ctypes
import ctypes.util
import errno
import logging
import os
import platform
import select
import struct
import time
from pathlib import Path
from typing import Any

from threatlens_agent.collectors.base import BaseCollector
from threatlens_agent.config import FileMonitorConfig
from threatlens_agent.models.events import (
    FILE_EVENT_CREATED,
    FILE_EVENT_DELETED,
    FILE_EVENT_MODIFIED,
    FILE_EVENT_RENAMED,
    Event,
    create_file_event,
)

logger = logging.getLogger(__name__)

# Linux inotify constants
IN_NONBLOCK = 0x00000800
IN_CLOEXEC = 0x00080000

IN_MODIFY = 0x00000002
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000

IN_ONLYDIR = 0x01000000
IN_DONT_FOLLOW = 0x02000000
IN_ISDIR = 0x40000000

WATCH_MASK = (
    IN_CREATE
    | IN_MODIFY
    | IN_DELETE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_DELETE_SELF
    | IN_MOVE_SELF
    | IN_DONT_FOLLOW
    | IN_ONLYDIR
)

# Struct format: int wd, uint32_t mask, uint32_t cookie, uint32_t len
INOTIFY_EVENT_HEADER_FMT = "iIII"
INOTIFY_EVENT_HEADER_SIZE = struct.calcsize(INOTIFY_EVENT_HEADER_FMT)

MAX_WATCH_DIRS = 512
MAX_BUFFER_READ_BYTES = 65536
MAX_EVENT_QUEUE_SIZE = 5000
RENAME_COOKIE_TTL_SECONDS = 5.0


def _load_libc():
    """Dynamically load libc for inotify syscall bindings."""
    libc_name = ctypes.util.find_library("c") or "libc.so.6"
    try:
        libc = ctypes.CDLL(libc_name, use_errno=True)
        if hasattr(libc, "inotify_init1") and hasattr(libc, "inotify_add_watch"):
            libc.inotify_init1.argtypes = [ctypes.c_int]
            libc.inotify_init1.restype = ctypes.c_int

            libc.inotify_add_watch.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint32,
            ]
            libc.inotify_add_watch.restype = ctypes.c_int

            libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
            libc.inotify_rm_watch.restype = ctypes.c_int
            return libc
    except Exception as exc:
        logger.debug("Failed to load libc inotify bindings: %s", exc)
    return None


class LinuxFileMonitorCollector(BaseCollector):
    """Incremental, non-destructive Linux file-system telemetry collector.

    Features:
    - Opt-in monitoring restricted strictly to configured paths.
    - IN_DONT_FOLLOW protection preventing symlink breakout.
    - Rename cookie pairing between IN_MOVED_FROM and IN_MOVED_TO.
    - Graceful permission and exclusion handling.
    - Bounded memory queue preventing unbounded event accumulation.
    """

    def __init__(
        self,
        device_id: str,
        config: FileMonitorConfig,
        hostname: str | None = None,
    ) -> None:
        self.device_id = device_id
        self.config = config
        self.hostname = hostname

        self._libc = _load_libc() if platform.system() == "Linux" else None
        self._inotify_fd: int | None = None
        self._watches: dict[int, Path] = {}
        self._path_to_wd: dict[Path, int] = {}
        self._cookie_jar: dict[int, tuple[Path, float]] = {}
        self._event_queue: collections.deque[Event] = collections.deque(
            maxlen=MAX_EVENT_QUEUE_SIZE
        )
        self._is_started: bool = False
        self._total_events_observed: int = 0
        self._total_events_dropped: int = 0

        self._diagnostics: dict[str, Any] = {
            "active_watches": 0,
            "monitored_directories": [],
            "failed_paths": [],
            "total_observed": 0,
            "dropped_overflow": 0,
            "is_supported": self.is_supported(),
        }

    @property
    def name(self) -> str:
        return "file_monitor"

    def is_supported(self) -> bool:
        """Check whether host is Linux and libc inotify bindings are available."""
        return platform.system() == "Linux" and self._libc is not None

    def start(self) -> None:
        """Initialize inotify file descriptor and register configured watches."""
        if not self.config.enabled:
            logger.info("LinuxFileMonitorCollector is disabled in config.")
            return

        if not self.is_supported():
            logger.warning(
                "LinuxFileMonitorCollector is not supported on this platform/kernel."
            )
            return

        try:
            self._inotify_fd = self._libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
            if self._inotify_fd < 0:
                err = ctypes.get_errno()
                logger.error("Failed to initialize inotify: %s", os.strerror(err))
                self._inotify_fd = None
                return
        except Exception as exc:
            logger.error("Error creating inotify descriptor: %s", exc)
            self._inotify_fd = None
            return

        self._setup_watches()
        self._is_started = True
        logger.info(
            "LinuxFileMonitorCollector started. Watching %d directory paths.",
            len(self._watches),
        )

    def _setup_watches(self) -> None:
        """Configure inotify watches for all valid configured paths."""
        if self._inotify_fd is None:
            return

        for p_str in self.config.monitored_paths:
            path = Path(p_str).expanduser()
            if not path.is_absolute():
                path = path.resolve()

            if not path.exists():
                logger.debug("Monitored path does not exist: %s", path)
                self._diagnostics["failed_paths"].append(
                    {"path": str(path), "reason": "not_found"}
                )
                continue

            if not path.is_dir():
                logger.debug("Monitored path is not a directory: %s", path)
                self._diagnostics["failed_paths"].append(
                    {"path": str(path), "reason": "not_a_directory"}
                )
                continue

            # Symlink guard
            if path.is_symlink() and not self.config.follow_symlinks:
                logger.warning(
                    "Skipping symlink directory per safety policy: %s", path
                )
                self._diagnostics["failed_paths"].append(
                    {"path": str(path), "reason": "symlink_rejected"}
                )
                continue

            if self._is_excluded(path):
                logger.debug("Path is excluded by configuration: %s", path)
                continue

            self._add_single_watch(path)

            if self.config.recursive:
                self._add_recursive_watches(path)

        self._diagnostics["active_watches"] = len(self._watches)
        self._diagnostics["monitored_directories"] = [
            str(p) for p in self._watches.values()
        ]

    def _add_single_watch(self, directory: Path) -> int | None:
        """Add watch for a single directory without following symlinks."""
        if self._inotify_fd is None:
            return None

        if len(self._watches) >= MAX_WATCH_DIRS:
            logger.warning(
                "Maximum directory watch limit reached (%d). Skipping %s",
                MAX_WATCH_DIRS,
                directory,
            )
            return None

        if directory in self._path_to_wd:
            return self._path_to_wd[directory]

        try:
            dir_bytes = str(directory).encode("utf-8")
            wd = self._libc.inotify_add_watch(self._inotify_fd, dir_bytes, WATCH_MASK)
            if wd < 0:
                err = ctypes.get_errno()
                logger.warning(
                    "inotify_add_watch failed for '%s': %s (errno %d)",
                    directory,
                    os.strerror(err),
                    err,
                )
                self._diagnostics["failed_paths"].append(
                    {"path": str(directory), "reason": os.strerror(err)}
                )
                return None

            self._watches[wd] = directory
            self._path_to_wd[directory] = wd
            return wd
        except Exception as exc:
            logger.warning("Failed to watch directory %s: %s", directory, exc)
            return None

    def _add_recursive_watches(self, root: Path) -> None:
        """Recursively add watches for child directories without following symlinks."""
        try:
            for dirpath, dirnames, _ in os.walk(str(root), followlinks=False):
                # Prune excluded directories in-place
                dirnames[:] = [
                    d
                    for d in dirnames
                    if not self._is_excluded(Path(dirpath) / d)
                    and not (Path(dirpath) / d).is_symlink()
                ]
                for d in dirnames:
                    child_path = Path(dirpath) / d
                    self._add_single_watch(child_path)
                    if len(self._watches) >= MAX_WATCH_DIRS:
                        return
        except (PermissionError, OSError) as exc:
            logger.debug("Permission error scanning subdirectories in %s: %s", root, exc)

    def _is_excluded(self, path: Path) -> bool:
        """Check if path matches any excluded pattern or path prefix."""
        path_str = str(path)
        name = path.name

        for exc in self.config.excluded_paths:
            if not exc:
                continue
            exc_p = str(Path(exc).expanduser())
            if path_str == exc_p or path_str.startswith(exc_p + "/"):
                return True

        for ext in self.config.excluded_extensions:
            clean_ext = ext if ext.startswith(".") else f".{ext}"
            if name.lower().endswith(clean_ext.lower()):
                return True

        return False

    def stop(self) -> None:
        """Gracefully release watches and close inotify file descriptor."""
        self._is_started = False
        if self._inotify_fd is not None:
            try:
                for wd in list(self._watches.keys()):
                    try:
                        self._libc.inotify_rm_watch(self._inotify_fd, wd)
                    except Exception:
                        pass
                os.close(self._inotify_fd)
            except Exception as exc:
                logger.debug("Error closing inotify descriptor: %s", exc)
            finally:
                self._inotify_fd = None
                self._watches.clear()
                self._path_to_wd.clear()
                self._cookie_jar.clear()

        self._diagnostics["active_watches"] = 0
        logger.info("LinuxFileMonitorCollector stopped.")

    def collect(self) -> list[Event]:
        """Poll inotify events and return a batch of newly observed Event instances."""
        if not self._is_started or self._inotify_fd is None:
            return []

        self._read_inotify_events()
        self._expire_stale_rename_cookies()

        batch: list[Event] = []
        max_batch = self.config.max_events_per_poll

        while self._event_queue and len(batch) < max_batch:
            batch.append(self._event_queue.popleft())

        return batch

    def _read_inotify_events(self) -> None:
        """Read pending raw inotify bytes and enqueue parsed normalized events."""
        if self._inotify_fd is None:
            return

        # Check readability with 0-second timeout (non-blocking poll)
        try:
            rlist, _, _ = select.select([self._inotify_fd], [], [], 0.0)
            if not rlist:
                return
        except (select.error, OSError) as exc:
            logger.debug("Select error on inotify fd: %s", exc)
            return

        try:
            raw_bytes = os.read(self._inotify_fd, MAX_BUFFER_READ_BYTES)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return
            logger.warning("Error reading inotify descriptor: %s", exc)
            return

        if not raw_bytes:
            return

        offset = 0
        total_len = len(raw_bytes)

        while offset + INOTIFY_EVENT_HEADER_SIZE <= total_len:
            wd, mask, cookie, name_len = struct.unpack_from(
                INOTIFY_EVENT_HEADER_FMT, raw_bytes, offset
            )
            offset += INOTIFY_EVENT_HEADER_SIZE

            raw_name = raw_bytes[offset : offset + name_len]
            offset += name_len

            # Extract clean filename, stripping null padding
            clean_name = raw_name.decode("utf-8", errors="replace").rstrip("\x00")

            dir_path = self._watches.get(wd)
            if dir_path is None:
                # Watch descriptor may have been removed or invalidated
                continue

            # Skip events on the watched directory itself if name is empty
            if not clean_name:
                continue

            full_path = dir_path / clean_name

            # Skip excluded paths or extensions
            if self._is_excluded(full_path):
                continue

            # Queue overflow event check
            if mask & IN_Q_OVERFLOW:
                self._total_events_dropped += 1
                self._diagnostics["dropped_overflow"] = self._total_events_dropped
                logger.warning("Inotify queue overflow detected. Some file events dropped.")
                continue

            # Directory created dynamically under recursive watch
            if (mask & IN_CREATE) and (mask & IN_ISDIR) and self.config.recursive:
                if not full_path.is_symlink():
                    self._add_single_watch(full_path)

            self._process_single_inotify_event(dir_path, clean_name, full_path, mask, cookie)

    def _process_single_inotify_event(
        self,
        dir_path: Path,
        clean_name: str,
        full_path: Path,
        mask: int,
        cookie: int,
    ) -> None:
        """Map raw inotify mask and cookie into normalized Phase 1 file events."""
        event_type: str | None = None
        previous_path: str | None = None

        if mask & IN_CREATE:
            event_type = FILE_EVENT_CREATED
        elif mask & IN_MODIFY:
            event_type = FILE_EVENT_MODIFIED
        elif mask & IN_DELETE:
            event_type = FILE_EVENT_DELETED
        elif mask & IN_MOVED_FROM:
            # First half of rename: record in cookie jar
            if cookie != 0:
                self._cookie_jar[cookie] = (full_path, time.time())
                return
            # Unpaired move-from without cookie: treat as deleted
            event_type = FILE_EVENT_DELETED
        elif mask & IN_MOVED_TO:
            # Second half of rename
            event_type = FILE_EVENT_RENAMED
            if cookie != 0 and cookie in self._cookie_jar:
                old_path, _ = self._cookie_jar.pop(cookie)
                previous_path = str(old_path)
            else:
                # Rename pairing unavailable (e.g. moved from unwatched dir)
                previous_path = None

        if event_type is None:
            return

        try:
            ev = create_file_event(
                device_id=self.device_id,
                event_type=event_type,
                file_path=str(full_path),
                previous_path=previous_path,
                source=self.name,
                hostname=self.hostname,
            )

            if len(self._event_queue) >= MAX_EVENT_QUEUE_SIZE:
                self._total_events_dropped += 1
                self._diagnostics["dropped_overflow"] = self._total_events_dropped
                logger.warning("Event queue limit reached. Dropping oldest file event.")
                self._event_queue.popleft()

            self._event_queue.append(ev)
            self._total_events_observed += 1
            self._diagnostics["total_observed"] = self._total_events_observed
        except Exception as exc:
            logger.debug("Failed to create file event for %s: %s", full_path, exc)

    def _expire_stale_rename_cookies(self) -> None:
        """Expire unpaired IN_MOVED_FROM entries after TTL."""
        now = time.time()
        expired_cookies = [
            c
            for c, (_, added_at) in self._cookie_jar.items()
            if now - added_at > RENAME_COOKIE_TTL_SECONDS
        ]
        for c in expired_cookies:
            # Unpaired move-out: file was moved outside watched scope
            self._cookie_jar.pop(c, None)

    def get_diagnostics(self) -> dict[str, Any]:
        """Return diagnostic metrics for agent health reporting."""
        self._diagnostics["active_watches"] = len(self._watches)
        self._diagnostics["total_observed"] = self._total_events_observed
        self._diagnostics["dropped_overflow"] = self._total_events_dropped
        self._diagnostics["is_supported"] = self.is_supported()
        return dict(self._diagnostics)
