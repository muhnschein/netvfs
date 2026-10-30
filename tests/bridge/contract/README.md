# netvfs-bridge protocol contract

Shared with consumers: lautta's `tests/bridge-contract/` holds same JSON and XML, byte for byte.

- `org.netvfs.Bridge1.xml`: introspection data bridge serves. Copy in `rust/netvfs-bridge-proto/org.netvfs.Bridge1.xml`; crate's `tests/contract.rs` fails when copies, method table or signals differ; `tst_contract` when running bridge serves anything else or reply/signal signature differs.
- `*.json`: golden message sequences, replayed against `netvfs-bridge` by `tst_contract` (libdbus, C++) and `rust/netvfs-bridge/tests/contract.rs` (zbus), with in-memory FakeBackend behind one account `account:1` (provider `fake`, name `Fake 1`, host `fake.example`); and against fake bridge by protocol crate's `tests/contract.rs`.

## Sequence format

```json
{
  "description": "...",
  "consent": "granted | denied | unknown",
  "files": { "path/in/the/fake/server": "content" },
  "steps": [
    { "call": "Stat", "sig": "saybs", "args": [...], "reply": [...] },
    { "call": "Stat", "sig": "saybs", "args": [...], "error": "org.netvfs.Error.NotFound" },
    { "signal": "ListDone", "args": [...] }
  ]
}
```

Steps in order, one connection. `call` waits for reply; `signal` waits for next signal of that name (others may arrive between).

Values: numbers for `y q u i x`; `true`/`false` for `b`; strings for `s`; `{"bytes": "text"}` (UTF-8) or `{"hex": "00ff"}` for `ay`; arrays for arrays and structs; objects for `a{sv}` (integers sent as `x`).

Matching: `"*"` anything; `"$name"` binds on first use, equal afterwards, substituted in later `args`; object matches keys it lists; array ending in `"..."` matches prefix.
