"""Fail-closed Studionet identity check."""
import json
import urllib.request

RPC = "https://studio.genlayer.com/api"
EXPECTED = 61999

payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}).encode()
request = urllib.request.Request(RPC, data=payload, headers={"Content-Type": "application/json"})
with urllib.request.urlopen(request, timeout=20) as response:
    body = json.loads(response.read().decode())
chain_id = int(body["result"], 16)
if chain_id != EXPECTED:
    raise SystemExit(f"ABORT: expected Studionet chain {EXPECTED}, got {chain_id}")
print(f"verified Studionet chain_id={chain_id} rpc={RPC}")
