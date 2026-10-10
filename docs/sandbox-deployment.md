# Sandbox deployment (CAPEv2)

The workbench never executes attachments on the analyst's machine. Execution happens in a disposable Windows VM managed by **CAPEv2** on a **separate Linux host**. The workbench talks to CAPE's REST API only, and only after an analyst explicitly submits a file.

> A container is **not** an adequate boundary for running arbitrary malicious attachments: containers share the host kernel and Windows malware needs a Windows kernel anyway. CAPE runs each sample in a full VM under KVM and restores a snapshot for every task.

## What was checked, and when

On 2026-10-05 against the CAPEv2 `master` branch:

- REST endpoints and response shapes in `web/apiv2/urls.py` and `web/apiv2/views.py`.
- `conf/default/api.conf.default` — several endpoints the adapter needs are **disabled by default** (see step 4).
- `conf/default/kvm.conf.default` and `routing.conf.default`.
- Docs at capev2.readthedocs.io: installer scripts `kvm-qemu.sh` and `cape2.sh`; KVM recommended; Windows guest agent requires **32-bit** Python 3 (3.10–3.12 preferred); `virsh snapshot-create-as` for snapshots; a single snapshot per guest is recommended.

The adapter was exercised against a mocked HTTP transport built from that source, **not** against a live CAPE. See [verification-status.md](verification-status.md).

## Topology

```
Analyst PC (Windows)                    Sandbox host (Ubuntu LTS, bare metal recommended)
  workbench 127.0.0.1 ─── mgmt NIC ───►  CAPE web/API :8000   (firewalled to the analyst PC only)
                                          │
                                          ├── virbr1  host-only, no forward, no NAT
                                          │     ├── Windows guest "win10"  192.168.56.101
                                          │     └── INetSim / resultserver  192.168.56.1
                                          └── (no bridge to the office LAN)
```

Supported host for the sandbox: a dedicated Linux machine with hardware virtualisation (Intel VT-x/AMD-V enabled in firmware). CAPE's installer targets Ubuntu LTS — check the CAPEv2 README for the release currently tested. Nested virtualisation (CAPE inside a VM on your Windows PC, e.g. VMware Workstation with "Virtualize Intel VT-x/EPT" or Hyper-V with `ExposeVirtualizationExtensions`) works for a lab but is slower and less isolated; never use the analyst workstation itself as the KVM host. Suggested minimum: 4 cores, 16 GB RAM, 200 GB SSD.

## 1. Install CAPE on the host

```bash
git clone https://github.com/kevoreilly/CAPEv2.git && cd CAPEv2/installer
sudo chmod a+x kvm-qemu.sh cape2.sh
# Replace the <WOOT> placeholders in kvm-qemu.sh with real ACPI strings first (anti-VM-detection), as the script explains.
sudo ./kvm-qemu.sh all <your-user> | tee kvm-qemu.log
sudo reboot
sudo ./cape2.sh base cape | tee cape.log
```

Don't upgrade packages the installer pinned. Run everything except the installers and `rooter.py` as the `cape` user.

## 2. Build the isolated network

Create a libvirt network with **no `<forward>` element** (host-only):

```xml
<!-- /tmp/cape-isolated.xml -->
<network>
  <name>cape-isolated</name>
  <bridge name="virbr1" stp="on" delay="0"/>
  <ip address="192.168.56.1" netmask="255.255.255.0"/>
</network>
```

```bash
virsh net-define /tmp/cape-isolated.xml && virsh net-start cape-isolated && virsh net-autostart cape-isolated
sudo iptables -I FORWARD -i virbr1 -j DROP     # belt and braces: nothing leaves the guest network
sudo apt install inetsim                         # simulated DNS/HTTP/SMTP on 192.168.56.1
```

Edit `/etc/inetsim/inetsim.conf`: `service_bind_address 192.168.56.1`, `dns_default_ip 192.168.56.1`. In CAPE `conf/routing.conf` (copy from `conf/default/`):

```ini
[routing]
route = inetsim
internet = none
[inetsim]
enabled = yes
server = 192.168.56.1
interface = virbr1
```

## 3. Prepare the Windows guest

1. Create a Windows 10 (or 11) VM attached **only** to `cape-isolated`. No shared folders, no clipboard/SPICE agent sharing, no USB redirection.
2. Use a local account that exists nowhere else. **Do not sign into any Microsoft, Google or company account**, and don't copy credentials, VPN profiles or browser profiles into it.
3. Install **32-bit** Python 3.10–3.12 ("Add to PATH"), then `python -m pip install Pillow` (screenshots).
4. Install what you want to observe: a PDF reader, Office 2016 32-bit (CAPE recommends 2010 SP2 or 2016). Disable their auto-update.
5. Disable Windows Update, Defender real-time protection, the firewall and UAC prompts; set AutoLogon (see CAPE guest docs "Additional configuration").
6. Static IP `192.168.56.101`, gateway and DNS `192.168.56.1`.
7. Copy CAPE's `agent/agent.py` into the guest (rename to `agent.pyw`), set it to start at logon with highest privileges, start it.
8. With the VM running and the agent listening, take **one** snapshot:

```bash
virsh snapshot-create-as --domain win10 --name clean
virsh snapshot-list win10     # exactly one: clean
```

## 4. Configure CAPE

`conf/kvm.conf`:

```ini
[kvm]
machines = win10
interface = virbr1
dsn = qemu:///system

[win10]
label = win10
platform = windows
ip = 192.168.56.101
arch = x64
tags = win10
snapshot = clean
```

`conf/api.conf` — the adapter needs these sections enabled (several are `no` by default):

```ini
[api]
token_auth_enabled = yes

[filecreate]
enabled = yes
[taskstatus]
enabled = yes
[taskreport]
enabled = yes
[taskscreenshot]
enabled = yes
[machineview]
enabled = yes
[cuckoostatus]
enabled = yes
[taskdelete]
enabled = yes        ; cancel before start
[user_stop]
enabled = yes        ; cancel / timeout while running
```

Snippets are also in `sandbox/cape-conf-snippets/`. Restart CAPE services, create a CAPE user, then get a token:

```bash
curl -d "username=<user>&password=<pass>" http://127.0.0.1:8000/apiv2/api-token-auth/
```

Firewall the CAPE web port so only the analyst PC can reach it (`ufw allow from <analyst-ip> to any port 8000`).

## 5. Point the workbench at CAPE

`backend\.env` on the analyst PC:

```ini
PHB_SANDBOX_MODE=cape
PHB_CAPE_URL=http://<sandbox-host-ip>:8000
PHB_CAPE_TOKEN=<token>
PHB_CAPE_MACHINE=win10
PHB_CAPE_SNAPSHOT=clean
PHB_CAPE_TIMEOUT_S=120
```

Restart `start.ps1`. The **Sandbox** page should show the engine as reachable and the guest as available. The token is never written to the database, history or logs (tested).

## 6. Verify with the harmless sample

1. Import `samples/emails/08_sandbox_verification.eml`.
2. Open `nemsec_sandbox_demo.exe`, enter your name, tick the confirmation, **Execute in sandbox**.
3. Expect: state *Execution finished*, a process `nemsec_sandbox_demo.exe`, a created file `…\Temp\NEMSEC_SANDBOX_DEMO_<pid>.txt`, no network activity, *Post-run reset: Verified*.
4. Repeat with `nemsec_sandbox_demo.bat` (CAPE runs it with its `bat` package): file `NEMSEC_SANDBOX_DEMO_BAT.txt`.
5. Check isolation from inside the guest once, manually: `ping <analyst-pc-ip>` and `nslookup example.com` must not reach real hosts (INetSim answers DNS with 192.168.56.1).

## Isolation checklist

- [ ] Guest NIC is only on the host-only `cape-isolated` network; host `FORWARD` from virbr1 is dropped.
- [ ] No shared folders, clipboard sharing, drag-and-drop or USB redirection.
- [ ] No personal or production accounts, credentials, tokens or VPN configs in the guest.
- [ ] The workbench database and evidence store are on the analyst PC, not reachable from the guest.
- [ ] Simulated services (INetSim) only; `internet = none` in routing.conf.
- [ ] Guest RAM/CPU set in the domain XML; run time limited by `PHB_CAPE_TIMEOUT_S` (`enforce_timeout=1` is sent).
- [ ] Exactly one clean snapshot named in both kvm.conf and `PHB_CAPE_SNAPSHOT`.

## Reset verification and quarantine

CAPE reverts the guest to its snapshot at the start of every task and powers it off afterwards. After each job the workbench polls `machines/view/<name>/` and accepts the guest as reset only when it is powered off, unlocked, and still configured with the expected snapshot. Until then the guest is `busy` and queued jobs wait. If that check fails, or doesn't pass within `PHB_CAPE_RESET_GRACE_S`:

- the job state becomes **Reset failed** (observations are kept, flagged);
- the guest is **quarantined** and every new submission is refused;
- an analyst must restore the guest on the host (`virsh snapshot-revert win10 clean`, check it boots and the agent answers), then release it on the Sandbox page with a written note, which goes to the history log.

What this does **not** do: it does not hash the VM disk or memory itself; it relies on CAPE/libvirt reporting state honestly. Reverting to a snapshot doesn't undo anything the sample did *outside* the guest (which the network isolation is there to prevent).

## Adapter contract

`backend/app/sandbox/base.py` defines `SandboxAdapter`:

| Method | Purpose |
|---|---|
| `capabilities()` | engine name, guest platform, content types it can run, what it records, network mode, caveats |
| `health(worker)` | engine reachable and guest known (and snapshot matches) |
| `submit(bytes, filename, timeout_s, worker)` → external id | hand the file to the engine |
| `status(external_id)` | `pending` / `running` / `finished` / `failed` / `unknown` |
| `cancel(external_id)` | stop a pending or running task |
| `results(external_id)` | normalised observations (schema in `base.py`) |
| `artifacts(external_id)` | screenshots etc. as bytes |
| `verify_reset(worker, external_id)` | `verified` / `pending` / `failed` |

To add another engine (e.g. a self-hosted DRAKVUF Sandbox), implement these and return it from `get_adapter()` in `sandbox/service.py`; the state machine, quarantine, UI and report work unchanged.
