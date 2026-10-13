# Test data

`sample_device_check.json` and `sample_job_claim.json` are real responses, captured
from a running instance of this server and then verified with the `verify`
subcommand. They are not hand-written: a fixture written by the same person who
wrote the signer proves only that the two agree.

They are committed for two reasons:

1. `verify -response` can be demonstrated against a real response without running
   the server.
2. A change to the canonical encoding that breaks signature compatibility with
   these recordings is caught, because `verify` will reject them.

`devices.json` is the registry used for the capture. Its HWID is the documented
shape — `AIO3-` followed by 64 hex characters — and its job hash is a placeholder
64-hex value, not a real APK hash. No real hardware id or artifact is included.

## Reproducing

```
$ ./run.sh
```

`run.sh` regenerates both files' equivalents from a fresh server instance each
time, verifies them, and asserts that an altered copy is rejected. The committed
copies are a snapshot of one such run.
