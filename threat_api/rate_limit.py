import threading
import time
from collections import defaultdict, deque


class SimpleRateLimiter:
    def __init__(self, limit_per_minute: int = 60):
        self.limit = limit_per_minute
        self.hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            q = self.hits[key]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True
