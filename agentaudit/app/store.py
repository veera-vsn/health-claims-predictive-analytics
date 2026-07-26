"""Ephemeral, in-memory result store.

Share links need a result to survive between the scan and the unfurl, but we
deliberately do not want a database of other people's system prompts sitting on
disk. So results live in a bounded LRU in the process and evaporate on restart.

What we keep is the rendered result and the tool names -- never the prompt text
itself, which is the part that would actually hurt if this store leaked.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict

#: Roughly a day of share links for a launch-day spike, at a few KB each.
MAX_ENTRIES = 1000

#: Share links stop resolving after this long.
TTL_SECONDS = 24 * 60 * 60


class ResultStore:
    def __init__(self, max_entries: int = MAX_ENTRIES, ttl: int = TTL_SECONDS):
        self._data: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_entries
        self._ttl = ttl

    def put(self, key: str, value: dict) -> None:
        with self._lock:
            self._data[key] = (time.time(), value)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def get(self, key: str) -> dict | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            created, value = entry
            if time.time() - created > self._ttl:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return value

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


store = ResultStore()
