# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2018 Quentin Pradet https://gist.github.com/pquentin/5d8f5408cdad73e589d85ba509091741

import asyncio
import time

import aiohttp

START = time.monotonic()


class RateLimiter:
    """Rate limits an HTTP client that would make get() and post() calls.

    Calls are rate-limited by host.
    https://quentin.pradet.me/blog/how-do-you-rate-limit-calls-with-aiohttp.html
    This class is not thread-safe."""

    RATE = 1  # one request per second
    MAX_TOKENS = 10

    def __init__(self, client):
        self.client = client
        self.tokens = self.MAX_TOKENS
        self.updated_at = time.monotonic()

    async def get(self, *args, **kwargs):
        await self.wait_for_token()
        now = time.monotonic() - START
        print(f"{now:.0f}s: ask {args[0]}")
        return self.client.get(*args, **kwargs)

    async def wait_for_token(self):
        while self.tokens < 1:
            self.add_new_tokens()
            await asyncio.sleep(0.1)
        self.tokens -= 1

    def add_new_tokens(self):
        now = time.monotonic()
        time_since_update = now - self.updated_at
        new_tokens = time_since_update * self.RATE
        if self.tokens + new_tokens >= 1:
            self.tokens = min(self.tokens + new_tokens, self.MAX_TOKENS)
            self.updated_at = now


async def fetch_one(client, i):
    url = f"https://httpbin.org/get?i={i}"
    # Watch out for the extra 'await' here!
    async with await client.get(url) as resp:
        resp = await resp.json()
        now = time.monotonic() - START
        print(f"{now:.0f}s: got {resp['args']}")


async def main():
    async with aiohttp.ClientSession() as client:
        client = RateLimiter(client)
        tasks = [asyncio.ensure_future(fetch_one(client, i)) for i in range(20)]
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    # Requires Python 3.7+
    asyncio.run(main())
