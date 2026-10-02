# netvfs-bridge protocol contract (SPEC-v2 XT-7)

Shared with consumers (the file browser's fake bridge replays the same files).

- `org.netvfs.Bridge1.xml`: the introspection data the bridge serves. A copy of
  `src/bridge/lib/org.netvfs.Bridge1.xml`; `tst_contract` fails when they differ, when the
  bridge's method table differs from it, or when a reply or signal has another signature.
- `*.json`: golden message sequences, replayed by `tst_contract` against the bridge with the
  in-memory FakeBackend behind one account, `account:1` (provider `fake`, name `Fake 1`, host
  `fake.example`).

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

Steps run in order on one connection. A `call` waits for its reply; a `signal` step waits for
the next signal of that name (signals of other names may arrive in between).

Values: numbers for `y q u i x`, `true`/`false` for `b`, strings for `s`, `{"bytes": "text"}`
(UTF-8) or `{"hex": "00ff"}` for `ay`, arrays for arrays and structs, objects for `a{sv}`
(integer values are sent as `x`).

Matching replies and signals: `"*"` matches anything; `"$name"` binds the value on first use
and must be equal afterwards (and is substituted in later `args`); an object matches the keys
it lists; an array whose last element is `"..."` matches a prefix.
