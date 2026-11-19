# ADA testing pipeline

Run native ADA browser diagnostics on authorized Mac and Linux workers. The
runner snapshots your six detector files and the frozen ADA frontend, starts a
test profile, and records the browser result, mode checks, and cleanup.

## Setup

- Install Python 3.9 or newer, OpenSSH, and `tar` on the controller. Local tests
  also use Node.js.
- Set up SSH key authentication and verify the worker's host key. Workers need
  Python 3.9+, Node.js with a global WebSocket implementation, the relevant
  browsers and vendor apps, and approved test account access.
- Configure Linux with display `:20` for vendor launches and
  `xvfb-run`, `Xvfb`, and `xauth` for headed Chrome controls.
- Supply your detector directory. It must contain `ads_power.js`,
  `dolphin_anty.js`, `gologin.js`, `headless.js`, `multilogin.js`, and
  `octo.js`. You can also place a suite at `solutions/<version>/src/commit`
  and pass its version. The detector files are required by the frontend even
  when you skip a vendor's live tests.

Store credentials on the workers in `/etc/ada-runner/credentials` on Linux or
`~/.ada-runner/credentials` on Mac. The runner reads the files for the selected
vendors:

| Vendor | Worker setup |
| --- | --- |
| Chrome control | Stock Chrome. Mac expects `/Applications/Google Chrome.app`. |
| AdsPower | Running local app and `adspower.env` containing `api_key` and optional loopback `api_root` (defaults to `http://127.0.0.1:50325`). |
| Dolphin Anty | Running local app on port 3001 and `dolphin.token`. For reuse-only testing, provide `dolphin.reuse_profiles.json` with `policy: "reuse-only"`, the worker's `host_os`, and approved `id`, `name`, and `platform` entries in `profiles`. |
| Multilogin | Running local API on port 45001 and `multilogin.env` containing `token`. The collector binds to the configured private worker IP to work with the browser's loopback masking. |
| Octo | Running local API on port 58888 and `octo.token`. Linux uses the cloud saved-profile route, while Mac uses a local disposable one-time profile. |
| GoLogin (optional) | Omit this vendor if the account lacks run access. If using it, provide `gologin.token` and the worker SDK. Linux reads `ADA_GOLOGIN_SDK_ENTRY` from the worker environment or uses `/opt/ada-runner/node_modules/gologin/src/index.js`. |

## Plan and run

A plan prints the roster and source, asset, and harness hashes. Supply a private
IPv4 SSH destination as `--worker user@address` or set `ADA_LINUX_WORKER` /
`ADA_MACOS_WORKER` in your local shell. The address below is an example.

```sh
python3 testing/run.py --solution /absolute/path/to/detectors --host linux \
  --worker operator@100.64.0.42 --vendors chrome_control --repeats 1
```

Add `--execute` to launch. `--repeats 1` runs one headed and one headless
visit. Run each worker separately. The first incomplete or failed vendor stops
that invocation. The worker lock prevents simultaneous runs. Results are saved
under `testing/runs/` with the source and frontend snapshots and per-vendor
assessments.

`SCOPED_PASS` requires the full case roster, correct product and payload mode,
a correct separate raw headless reading, and verified cleanup. The raw reading
uses a separate document. These are local diagnostics and cannot verify private
mainnet gates.

## Existing headed Octo on Mac

Start the three approved saved profiles. Put their lowercase, dashless UUIDs in
a local file outside the repository as a JSON array of three strings.

```sh
python3 testing/run_existing_octo.py --solution /absolute/path/to/detectors \
  --worker operator@100.64.0.43 --approved-profiles /private/path/octo-profiles.json
```

Add `--execute` to run two visits per profile. The runner binds each profile
to its PID, tracks each new tab by ID, and verifies closure after the visit.
Existing tabs and the running profiles stay open. An unverified closure stops
the run. This procedure measures headed payloads and is separate from the fresh
launch and headless paths.

## Local checks and evidence replay

```sh
python3 -m unittest discover -s testing -p 'test*.py'
python3 testing/assess_native.py /path/to/run/source /path/to/summary.json \
  --assets-directory /path/to/run/assets --output /tmp/assessment.json
```

The local tests use fixtures. Vendor credentials, worker configuration, profile
IDs, saved test receipts, and detector suites are kept outside this repository.
The frozen ADA challenge frontend is distributed with its upstream license in
`LICENSE-ADA-CHALLENGE.txt`.
