"""Opt-in, cookie-authenticated Bitcoin Core JSON-RPC broadcasting."""

from __future__ import annotations

import base64
import itertools
import json
import math
import os
from pathlib import Path
import stat
import threading
from typing import Any, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
import ipaddress
import re
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)


_VALID_CHAINS = frozenset(("main", "test", "testnet4", "signet", "regtest"))
_TXID = re.compile(r"^[0-9a-fA-F]{64}$")


class BitcoinRpcError(RuntimeError):
    """Raised when Bitcoin Core RPC cannot safely complete an operation."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class BitcoinCoreRpcClient:
    """A guarded client for a Bitcoin Core node's cookie-authenticated RPC.

    Plain HTTP is restricted to loopback hosts. Remote endpoints must use HTTPS
    with normal certificate verification. Broadcasting requires an explicitly
    selected chain, a successful ``testmempoolaccept``, and a Core cookie file.
    """

    def __init__(
        self,
        url: str,
        cookie_file: str | os.PathLike[str],
        *,
        expected_chain: str,
        timeout: float = 15.0,
        max_fee_rate_btc_per_kvb: float = 0.1,
    ) -> None:
        if not isinstance(url, str):
            raise TypeError("url must be a string")
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("url must be an HTTP or HTTPS JSON-RPC endpoint")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("credentials must come from the cookie file, not the URL")
        if parsed.query or parsed.fragment:
            raise ValueError("url must not contain a query or fragment")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("url contains an invalid port") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("url port must be between 1 and 65535")
        if parsed.scheme == "http" and not self._is_loopback_host(parsed.hostname):
            raise ValueError("unencrypted HTTP RPC is allowed only on loopback")
        if expected_chain not in _VALID_CHAINS:
            raise ValueError(f"expected_chain must be one of {sorted(_VALID_CHAINS)}")
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a positive finite number")
        if (
            not isinstance(max_fee_rate_btc_per_kvb, (int, float))
            or not math.isfinite(max_fee_rate_btc_per_kvb)
            or max_fee_rate_btc_per_kvb <= 0
        ):
            raise ValueError("max_fee_rate_btc_per_kvb must be positive and finite")

        self.url = url
        self.cookie_file = Path(cookie_file)
        self.expected_chain = expected_chain
        self.timeout = float(timeout)
        self.max_fee_rate_btc_per_kvb = float(max_fee_rate_btc_per_kvb)
        self._ids = itertools.count(1)
        self._id_lock = threading.Lock()
        self._opener = build_opener(ProxyHandler({}), _NoRedirectHandler())

    @staticmethod
    def _is_loopback_host(host: str) -> bool:
        normalized = host.strip("[]").lower()
        if normalized == "localhost":
            return True
        try:
            return ipaddress.ip_address(normalized).is_loopback
        except ValueError:
            return False

    def _authorization_header(self) -> str:
        try:
            info = self.cookie_file.stat()
            if not stat.S_ISREG(info.st_mode):
                raise BitcoinRpcError("Bitcoin Core cookie path is not a regular file")
            if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
                raise BitcoinRpcError("Bitcoin Core cookie file permissions are too broad")
            cookie = self.cookie_file.read_bytes().strip()
        except BitcoinRpcError:
            raise
        except OSError as exc:
            raise BitcoinRpcError("Bitcoin Core cookie file could not be read") from exc
        if b":" not in cookie or b"\n" in cookie or b"\r" in cookie:
            raise BitcoinRpcError("Bitcoin Core cookie file has an invalid format")
        username, password = cookie.split(b":", 1)
        if not username or not password:
            raise BitcoinRpcError("Bitcoin Core cookie file has an invalid format")
        return "Basic " + base64.b64encode(cookie).decode("ascii")

    def call(self, method: str, params: Optional[list[Any]] = None) -> Any:
        """Call one JSON-RPC method without exposing cookie or response secrets."""
        if not isinstance(method, str) or not method or any(c.isspace() for c in method):
            raise ValueError("method must be a non-empty RPC method name")
        if params is None:
            params = []
        if not isinstance(params, list):
            raise TypeError("params must be a list")
        with self._id_lock:
            request_id = next(self._ids)
        body = json.dumps(
            {"jsonrpc": "1.0", "id": request_id, "method": method, "params": params},
            separators=(",", ":"),
        ).encode("utf-8")
        request = Request(
            self.url,
            data=body,
            headers={
                "Authorization": self._authorization_header(),
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                response_body = response.read(4 * 1024 * 1024 + 1)
        except HTTPError as exc:
            if exc.code == 401:
                raise BitcoinRpcError("Bitcoin Core RPC authentication failed") from None
            raise BitcoinRpcError(
                f"Bitcoin Core RPC returned HTTP status {exc.code}"
            ) from None
        except (URLError, TimeoutError, OSError) as exc:
            raise BitcoinRpcError("Bitcoin Core RPC connection failed") from None
        if len(response_body) > 4 * 1024 * 1024:
            raise BitcoinRpcError("Bitcoin Core RPC response exceeded the size limit")
        try:
            payload = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise BitcoinRpcError("Bitcoin Core RPC returned invalid JSON") from None
        if not isinstance(payload, Mapping) or payload.get("id") != request_id:
            raise BitcoinRpcError("Bitcoin Core RPC response did not match the request")
        error = payload.get("error")
        if error is not None:
            code = error.get("code") if isinstance(error, Mapping) else None
            message = error.get("message") if isinstance(error, Mapping) else None
            safe_message = message if isinstance(message, str) else "node rejected the RPC"
            raise BitcoinRpcError(f"Bitcoin Core RPC error {code}: {safe_message}")
        if "result" not in payload:
            raise BitcoinRpcError("Bitcoin Core RPC response did not contain a result")
        return payload["result"]

    def broadcast_transaction(self, raw_transaction: bytes) -> str:
        """Check network/mempool policy, broadcast, and return the txid."""
        if not isinstance(raw_transaction, (bytes, bytearray, memoryview)):
            raise TypeError("raw_transaction must be bytes-like")
        raw_transaction = bytes(raw_transaction)
        if not raw_transaction:
            raise ValueError("raw_transaction must not be empty")
        blockchain = self.call("getblockchaininfo")
        if not isinstance(blockchain, Mapping):
            raise BitcoinRpcError("Bitcoin Core returned invalid blockchain information")
        chain = blockchain.get("chain")
        if chain != self.expected_chain:
            raise BitcoinRpcError(
                f"Connected node is on chain {chain!r}, expected {self.expected_chain!r}"
            )
        transaction_hex = raw_transaction.hex()
        accepted = self.call("testmempoolaccept", [[transaction_hex]])
        if (
            not isinstance(accepted, list)
            or len(accepted) != 1
            or not isinstance(accepted[0], Mapping)
        ):
            raise BitcoinRpcError("Bitcoin Core returned an invalid mempool test result")
        if accepted[0].get("allowed") is not True:
            reason = accepted[0].get("reject-reason")
            if not isinstance(reason, str):
                reason = "node did not accept the transaction"
            raise BitcoinRpcError(f"Bitcoin Core rejected transaction: {reason}")
        txid = self.call(
            "sendrawtransaction",
            [transaction_hex, self.max_fee_rate_btc_per_kvb],
        )
        if not isinstance(txid, str) or _TXID.fullmatch(txid) is None:
            raise BitcoinRpcError("Bitcoin Core returned an invalid transaction ID")
        return txid.lower()


__all__ = ["BitcoinCoreRpcClient", "BitcoinRpcError"]