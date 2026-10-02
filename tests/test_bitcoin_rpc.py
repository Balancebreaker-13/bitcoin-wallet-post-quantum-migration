"""Tests for authenticated, opt-in Bitcoin Core RPC broadcasting."""

import json
import os
from pathlib import Path

import pytest

from src.bitcoin.integration import BitcoinTransactionBuilder
from src.bitcoin.rpc import BitcoinCoreRpcClient, BitcoinRpcError


class _Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, size=-1):
        return self.payload[:size]


class _FakeOpener:
    def __init__(self, handler):
        self.handler = handler
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        body = json.loads(request.data)
        result = self.handler(body["method"], body["params"])
        return _Response({"result": result, "error": None, "id": body["id"]})


def _client(tmp_path: Path, handler, *, chain="regtest", url="http://127.0.0.1:18443"):
    cookie = tmp_path / ".cookie"
    cookie.write_text("rpcuser:private-cookie-value")
    os.chmod(cookie, 0o600)
    client = BitcoinCoreRpcClient(
        url,
        cookie,
        expected_chain=chain,
    )
    fake = _FakeOpener(handler)
    client._opener = fake
    return client, fake


def test_rpc_transport_refuses_plain_http_for_remote_hosts(tmp_path):
    cookie = tmp_path / ".cookie"
    cookie.write_text("user:password")
    os.chmod(cookie, 0o600)
    with pytest.raises(ValueError, match="loopback"):
        BitcoinCoreRpcClient(
            "http://bitcoin.example:8332",
            cookie,
            expected_chain="main",
        )


def test_rpc_transport_refuses_credentials_embedded_in_url(tmp_path):
    cookie = tmp_path / ".cookie"
    cookie.write_text("user:password")
    os.chmod(cookie, 0o600)
    with pytest.raises(ValueError, match="cookie file"):
        BitcoinCoreRpcClient(
            "http://user:password@localhost:8332",
            cookie,
            expected_chain="main",
        )


def test_builder_broadcast_requires_explicit_rpc_client():
    with pytest.raises(NotImplementedError, match="authenticated"):
        BitcoinTransactionBuilder().broadcast_transaction(b"raw-signed-tx")


def test_rpc_broadcast_checks_chain_mempool_and_sends_transaction(tmp_path):
    calls = []

    def handler(method, params):
        calls.append((method, params))
        if method == "getblockchaininfo":
            return {"chain": "regtest"}
        if method == "testmempoolaccept":
            return [{"allowed": True}]
        if method == "sendrawtransaction":
            return "ab" * 32
        raise AssertionError(method)

    client, fake = _client(tmp_path, handler)
    txid = BitcoinTransactionBuilder(rpc_client=client).broadcast_transaction(
        b"\x02\x00\x00\x00signed"
    )
    assert txid == "ab" * 32
    assert [method for method, _ in calls] == [
        "getblockchaininfo",
        "testmempoolaccept",
        "sendrawtransaction",
    ]
    assert calls[1][1] == [["020000007369676e6564"]]
    request, timeout = fake.requests[0]
    assert request.get_header("Authorization").startswith("Basic ")
    assert timeout == 15.0


def test_rpc_refuses_wrong_chain_and_mempool_rejection(tmp_path):
    client, fake = _client(
        tmp_path,
        lambda method, params: {"chain": "main"} if method == "getblockchaininfo" else [],
    )
    with pytest.raises(BitcoinRpcError, match="expected 'regtest'"):
        client.broadcast_transaction(b"raw")
    assert len(fake.requests) == 1

    client, fake = _client(
        tmp_path,
        lambda method, params: (
            {"chain": "regtest"}
            if method == "getblockchaininfo"
            else [{"allowed": False, "reject-reason": "mandatory-script-verify-flag-failed"}]
        ),
    )
    with pytest.raises(BitcoinRpcError, match="rejected transaction"):
        client.broadcast_transaction(b"raw")
    assert len(fake.requests) == 2


def test_rpc_requires_private_cookie_permissions(tmp_path):
    client, _ = _client(
        tmp_path,
        lambda method, params: {"chain": "regtest"},
    )
    os.chmod(client.cookie_file, 0o644)
    with pytest.raises(BitcoinRpcError, match="permissions"):
        client.call("getblockchaininfo")