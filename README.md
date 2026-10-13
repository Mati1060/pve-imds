# pve-imds

An OpenStack, EC2 and NoCloud IMDS (Instance Metadata Service) compatible metadata service for virtual machines running in Proxmox.

With `pve-imds`, an unmodified Linux [cloud image](https://cloud-images.ubuntu.com/) running [cloud-init](https://docs.cloud-init.io/en/latest/explanation/introduction.html) can reach `http://169.254.169.254` to retrieve not only instance metadata but also **custom [user data](https://docs.cloud-init.io/en/latest/explanation/format/index.html)** stored in the Proxmox VM *Notes* field. `pve-imds` also supports a **signed identity document** that a VM can use to authenticate to a service like Vault.

## Quick start

1. Download the [latest release](https://github.com/wyattanderson/pve-imds/releases/latest) of `pve-imds` and install it. This snippet will fetch the latest `.deb` package artifact URL from the GitHub API, download, and install it. It's all here for the sake of transparency over a `curl ... | sudo bash` alternative.

```bash
# Protip: hit the ⧉ button to copy to the clipboard then paste the whole command.
SUDO=$(command -v sudo >/dev/null 2>&1 && echo sudo || echo '') && \
tmp=$(mktemp --suffix=.deb) && \
curl -fL "$(curl -fsSL https://api.github.com/repos/wyattanderson/pve-imds/releases/latest \
    | python3 -c 'import sys,json;print(next(a["browser_download_url"] for a in json.load(sys.stdin)["assets"] if a["name"].endswith(".deb")))')" -o "$tmp" && \
$SUDO dpkg -i "$tmp" && \
rm -f "$tmp"
```

2. Download the latest cloud image from your distribution of choice. Here, we'll use Ubuntu 24.04 LTS:

```bash
curl -LO https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
```

3. Import the cloud image as a new VM template. Substitute `local-lvm` and `vmbr0` with your storage and bridge interface of choice.

> [!NOTE]
> The `--smbios1` configuration is necessary in order to convince `cloud-init` to look out over the network for configuration instead of expecting a CDROM.

```bash
qm create $(pvesh get /cluster/nextid) \
    --name noble-server-cloudimg-amd64 \
    --agent enabled=1 \
    --cpu cputype=host \
    --memory 2048 \
    --scsi0 local-lvm:0,import-from=$(pwd)/noble-server-cloudimg-amd64.img \
    --scsihw virtio-scsi-single \
    --smbios1 base64=1,product=$(echo -n 'OpenStack Nova' | base64) \
    --template 1 \
    --storage local-lvm \
    --net0 bridge=vmbr0,model=virtio
```

4. Note the VM ID of your new template. Set some user data and clone your template into a new VM:

```bash
cat << EOF > user-data
#cloud-config
package_update: true
packages:
  - qemu-guest-agent
runcmd:
  - [ systemctl, enable, --now, --no-block, qemu-guest-agent.service ]
ssh_authorized_keys:
  # replace this with your own SSH public key
  - ssh-ed25519 AAAAC3NzaC1lZ...
EOF

# pve-imds reads user data from the contents 
qm clone <TEMPLATE VMID> $(pvesh get /cluster/nextid) --description "$(echo '<!--#user-data'; cat user-data; echo '-->')" --name "my-test-vm"
```

5. Boot your new VM, look for the IP as reported by `qemu-guest-agent`, and try SSHing in. Verify that everything is working:

```bash
curl http://169.254.169.254/openstack/latest/meta_data.json
```

## Why network-based configuration?

The ISO image approach that Proxmox uses (and that I used before this by generating my own ISO images with my own user data) isn't dynamic. With this approach, metadata is up-to-date immediately. Change a tag? Add user data? Immediately visible in the instance without regenerating the image.

## Why not use the cloud-init support built-in to Proxmox?

Custom user data affords an incredibly powerful way to provision machines with `cloud-init`. It is extensively customizable and is an industry-standard method for complete unattended provisioning of machines.

Proxmox has [basic support for cloud-init](https://pve.proxmox.com/wiki/Cloud-Init_Support) that works by generating an ISO image and attaching it to the VM. Unfortunately, Proxmox only lets you configure custom user data if you provide it via a snippet file from a storage source that supports snippets. This adds complexity, especially around replication.

With `pve-imds`, you can embed custom user data in the *Notes* field of a VM (inside a comment tag, so it isn't visible). This field is stored in the VM's replicated configuration file in `/etc/pve/qemu-server/<VMID>.conf`. Additionally, `pve-imds` serves all of the VM's metadata, **including VM tags** which can be fed into a config management tool like Ansible or Salt to specify things like machine roles or environments.

### Instance identity documents and trust

For me, these capabilites alone were valuable enough to develop `pve-imds`. However, I also wanted a pathway to something like the AWS EC2 [instance identity document](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html), which provides an external mechanism for **cryptographically verifying instance metadata**. So, if you're using Proxmox tags to specify that a VM is a `mysql` server in the `prod` environment, that VM can *prove it* to another service that trusts a public key.

## JWT-SVID identity tokens

VMs can use `pve-imds` to issue a short-lived [JWT-SVID](https://spiffe.io/docs/latest/spiffe-specs/jwt-svid/) token. You can use these tokens to authenticate to a service like [Vault](https://developer.hashicorp.com/vault/docs/auth/jwt).

```
# From inside the VM:
curl -s -X POST http://169.254.169.254/pve-imds/jwtsvid \
  -d "audience=https://vault.example.com"
# eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiIsInR5cCI6IkpXVCJ9...
```

When decoded, a token contains these claims:

```json
{
  "aud": "foo",
  "exp": 1775087893,
  "hostname": "test-host",
  "iat": 1775087593,
  "jti": "6023722e-2af9-4f92-8a45-1fb98ccf4e11",
  "meta": {
    "another-tag": "",
    "centos-stream-9": "",
    "pve:node": "test-node",
    "pve:vmid": "106"
  },
  "name": "test-host",
  "sub": "spiffe://test-node/106",
  "uuid": "2c8c7c76-a26c-4eb7-b04c-bf52bc095b81"
}
```

A relying party can verify the signature of this token using the JWKS endpoint at `http://169.254.169.254/.well-known/jwks.json`. Rather than managing its own signing keys, `pve-imds` uses Proxmox's PKI. Tokens are signed using the node's private key, and the public keys of all nodes in the cluster are made available via the JWKS endpoint.

## NoCloud datasource

`pve-imds` also serves the cloud-init [NoCloud](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html) datasource over HTTP under `http://169.254.169.254/nocloud/`, for every VM and regardless of the `emulate` setting. This is what lets [Talos Linux](https://www.talos.dev/) `nocloud` images, which support SecureBoot (unlike the Talos OpenStack image), and any cloud-init image provision from `pve-imds`.

| Path | Response |
|---|---|
| `/nocloud/` (or `/nocloud`) | List of the files below |
| `/nocloud/meta-data` | YAML with `instance-id` (the SMBIOS UUID, falling back to the VMID) and `local-hostname` (the VM name) |
| `/nocloud/user-data` | The same user data as the OpenStack and EC2 endpoints, after [templating](#templated-user-data-with-openbao-secrets). Empty (200) when the VM has none |
| `/nocloud/vendor-data` | Empty |
| `/nocloud/network-config` | The VM's `<!--#network-config` Notes block as written (v1 or v2, with or without the top-level `network:` key), or, without one, DHCPv4 on every NIC matched by MAC address |

Missing user-data is an empty 200 rather than a 404 because cloud-init's NoCloud datasource fails on a 404, while both cloud-init and Talos treat an empty body as "no user-data". `network-config` is always served because Talos retries a 404 for several minutes and only applies the hostname when it receives a network config.

To point a VM at it, set its SMBIOS serial number. Proxmox only accepts base64 in the `serial` field, so encode it and add `base64=1`. `qm set --smbios1` replaces the whole `smbios1` value, so keep the VM's existing UUID:

```bash
VMID=123
UUID=$(qm config $VMID | sed -n 's/^smbios1:.*uuid=\([^,]*\).*/\1/p')
SERIAL='ds=nocloud-net;s=http://169.254.169.254/nocloud/;h=talos-worker-1'
qm set $VMID --smbios1 "uuid=$UUID,serial=$(echo -n "$SERIAL" | base64 -w0),base64=1"
```

`h=` is optional; when set, it overrides the hostname from `meta-data`. The trailing `/` on the seed URL matters for older cloud-init releases; Talos and cloud-init 23.1+ add it if it is missing.

### Static network config

To give a VM a static address instead of DHCP, add a `<!--#network-config` block to its Notes, next to any `<!--#user-data` block. It holds a standard cloud-init [network config](https://docs.cloud-init.io/en/latest/reference/network-config.html), v1 or v2:

```
<!--#network-config
network:
  version: 2
  ethernets:
    net0:
      match:
        macaddress: "bc:24:11:00:00:01"
      addresses:
        - 192.168.1.10/24
      routes:
        - to: 0.0.0.0/0
          via: 192.168.1.1
      nameservers:
        addresses: [192.168.1.1]
-->
```

The block is served as written; `pve-imds` only checks that it is YAML with `version: 1` or `2`. If it isn't, the VM gets the DHCP default instead and the problem is logged with the VMID, so check `journalctl -u pve-imds` if a static address doesn't apply.

### Talos

With Talos, a VM without user-data gets its hostname and boots into maintenance mode, ready for `talosctl apply-config`. A VM with a machine config in its Notes boots straight into it. To keep the secrets in that config out of Notes, use templated user-data.

Set `nocloud.enabled: false` to disable the endpoint.

## Templated user-data with OpenBao secrets

Notes are readable by anyone with `VM.Audit` on the VM and are included in backups, so they are not a good place for secrets such as a Talos machine config's tokens and keys. Instead, user data can contain placeholders that `pve-imds` fills in from an [OpenBao](https://openbao.org/) (or Vault) KV v2 secrets engine when the VM fetches it:

```
<!--#user-data secrets=worker
version: v1alpha1
machine:
  type: worker
  token: {{ secret "machine_token" }}
  ca:
    crt: {{ secret "machine_ca_crt" }}
cluster:
  token: {{ secret "cluster_token" }}
  # ...the rest of your worker config...
-->
```

- `secrets=<set>` on the opening line names the **secret set**. Without it, user data is served exactly as written and no placeholders are processed, so cloud-init Jinja templates are unaffected. The attribute must be on the same line as `<!--#user-data`.
- The set is read from a KV path inside the VM's **scope**, which is either its resource pool or one of its tags (see [Scoping secrets](#scoping-secrets-pools-or-tags)). Both come from Proxmox, never from anything the VM controls.
- `{{ secret "<field>" }}` is replaced with that field of the set. Whitespace inside the braces is allowed. Nothing else is interpreted: other `{{ ... }}` text is left as is, and values are inserted verbatim, so quote or indent them as your format requires (Talos expects base64 for certificates and keys, which keeps them on one line).
- Set names may contain only letters, digits, `-` and `_` (up to 64 characters).
- Templated user-data applies to the NoCloud, OpenStack and EC2 user-data endpoints alike.
- The Notes field is limited to 8 KiB by Proxmox, which comfortably fits a worker config without its secrets.

For the example above, in pool `k8s-dmz-01`:

```bash
bao kv put kv/pve-imds/pools/k8s-dmz-01/worker \
    machine_token=... machine_ca_crt=... cluster_token=...
```

### Scoping secrets: pools or tags

`secrets.path_template` decides what a VM's secret sets are scoped to. It must contain `{name}` (the set name) and exactly one of:

- **`{pool}`** (default, `kv/data/pve-imds/pools/{pool}/{name}`): the VM's Proxmox [resource pool](https://pve.proxmox.com/wiki/User_Management#pveum_pools), read from `/etc/pve/user.cfg`. Nested pools (`parent/child`) become nested paths. A VM must be in a pool to use templating.
- **`{tag}`** (e.g. `kv/data/pve-imds/tags/{tag}/{name}`): the VM tag that starts with `secrets.tag_prefix` (default `pve-imds-`), without the prefix and lowercased. A VM tagged `pve-imds-k8s-dmz-01` reads `kv/data/pve-imds/tags/k8s-dmz-01/<set>`. Other tags are ignored. A VM with no such tag, or with more than one, gets a 503.

  By default (`secrets.require_registered_tags: true`) the tag must also be listed in `registered-tags` in `/etc/pve/datacenter.cfg` (in the GUI under *Datacenter → Options*, or with `pvesh set /cluster/options --registered-tags 'pve-imds-k8s-dmz-01;...'`). Registered tags can only be set or removed by users with `Sys.Modify` on `/`. Without that, anyone with `VM.Config.Options` on any VM could tag it and read that scope's secrets. Turn the check off only if everyone who can edit VMs is trusted with all secrets.

  `--registered-tags` replaces the whole list, so include the tags that are already registered (`pvesh get /cluster/options` shows them). Tags are matched case-insensitively, as in Proxmox, unless `tag-style` sets `case-sensitive=1`.

  Tag scoping fits well with [JWT-SVID](#jwt-svid-identity-tokens) roles that are bound to tags; register those tags for the same reason.

Pool membership, tags and `registered-tags` are re-read on every templated request, so changes, including ones made on other cluster nodes, take effect immediately.

### Failure behaviour

Rendering fails closed. The user-data endpoints return `503 Service Unavailable` with a `Retry-After` header, never a partially rendered or unrendered config, when:

- OpenBao is unreachable, returns an error, or rejects the token,
- the secret set or a referenced field doesn't exist (only string fields are used),
- the set name is invalid,
- the VM has no scope: it is not in a pool, or it has no, several, or an unregistered scope tag, or
- the Notes use `secrets=` but `secrets.enabled` is off.

cloud-init honours `Retry-After`; Talos keeps retrying until it gets the config rather than falling into maintenance mode. `pve-imds` logs the VMID, scope (pool or tag), set name and outcome of every templated request, never user-data or secret values.

### Security model

- **Secrets are bound to the VM's scope.** A VM can only ever receive secrets from its own scope's prefix, whatever its Notes contain, so Proxmox permissions decide who can give a VM access to which secrets: `Pool.Allocate` on the pool for pool scoping, `Sys.Modify` on `/` for registered scope tags. Anyone who can put a VM into a scope, or edit the Notes of a VM in a scope, can obtain that scope's secrets through the VM.
- **Keep secrets out of Notes.** Notes are visible to `VM.Audit` and included in backups; set names and placeholders are not sensitive.
- **Give `pve-imds` a read-only token.** It needs nothing beyond read access to its prefix, for example:

  ```hcl
  path "kv/data/pve-imds/pools/*" {   # or kv/data/pve-imds/tags/*
    capabilities = ["read"]
  }
  ```

- **Separate clusters.** If several Proxmox clusters share one OpenBao, give each cluster its own [namespace](https://openbao.org/docs/concepts/namespaces/) with `secrets.namespace` (OpenBao 2.3+ or Vault Enterprise), so one cluster's token cannot read another's secrets. Without namespaces, use a different `secrets.path_template` prefix per cluster and scope each cluster's policy to it.

### Token and OpenBao Agent

`pve-imds` has no authentication logic of its own. It reads a token from `secrets.token_file` on every request, so a token renewed by [OpenBao Agent](https://openbao.org/docs/agent-and-proxy/agent/) takes effect immediately. The service runs as a dynamic user that is a member of the `pve-imds-token` group (created by the package), so make the token file readable by that group, for example with an agent file sink in a setgid directory:

```bash
install -d -m 2750 -o root -g pve-imds-token /run/openbao-agent-pve-imds
```

```hcl
sink "file" {
  config = {
    path = "/run/openbao-agent-pve-imds/token"
    mode = 0640
  }
}
```

The service unit only allows IPv4 sockets. If OpenBao is only reachable over IPv6, add a drop-in with `systemctl edit pve-imds`:

```ini
[Service]
RestrictAddressFamilies=AF_XDP AF_NETLINK AF_UNIX AF_INET AF_INET6
```

### Setting it up

On every Proxmox node that runs `pve-imds`:

1. Run OpenBao Agent with a file sink that writes the token where the `pve-imds-token` group can read it, as above, and give its role a read-only policy for the secrets prefix (see [Security model](#security-model)).
2. Enable templating in `/etc/pve-imds/config.yaml` (see [Configuration](#configuration)) and restart the service:

   ```yaml
   secrets:
     enabled: true
     address: https://openbao.example.com:8200
     token_file: /run/openbao-agent-pve-imds/token
     # for tag scoping, also:
     # path_template: kv/data/pve-imds/tags/{tag}/{name}
   ```

   ```bash
   systemctl restart pve-imds
   journalctl -u pve-imds -n 20   # a bad secrets config stops the service from starting
   ```

Then, once per scope and VM:

3. Store the secret set: `bao kv put kv/pve-imds/pools/<pool>/<set> field=value ...` (or `kv/pve-imds/tags/<scope>/<set>`).
4. Put the VM in the pool, or register the scope tag and add it to the VM:

   ```bash
   pvesh set /pools --poolid <pool> --vms <VMID>  # pool scoping
   qm set <VMID> --tags 'pve-imds-<scope>'        # tag scoping; replaces the VM's tags
   ```

5. Add `secrets=<set>` and the `{{ secret "<field>" }}` placeholders to the VM's `<!--#user-data` block.
6. Check the result from inside the VM with `curl -i http://169.254.169.254/nocloud/user-data`. A 503 means rendering failed; the `pve-imds` log on the VM's node has the reason as `outcome` (for example `vm_not_in_pool`, `tag_not_registered` or `secret_fetch_failed`).

## Configuration

`pve-imds` reads `/etc/pve-imds/config.yaml` if it exists (or the file given with `--config`). Every option can also be set with an environment variable, e.g. `PVE_IMDS_SECRETS_ENABLED=true`. The options for NoCloud and templated user-data:

```yaml
nocloud:
  enabled: true            # serve /nocloud/ (default: true)

secrets:
  enabled: false           # render secrets= user-data (default: false)
  address: https://openbao.example.com:8200   # must be https
  namespace: ""            # optional, sent as X-Vault-Namespace
  ca_file: /etc/pve-imds/openbao-ca.pem       # optional; default: system CAs
  token_file: /run/openbao-agent-pve-imds/token
  path_template: kv/data/pve-imds/pools/{pool}/{name}  # API path below /v1/; {pool} or {tag}
  tag_prefix: pve-imds-    # with {tag}: the tag that selects the scope
  require_registered_tags: true  # with {tag}: only trust registered tags
  cache_ttl: 60s           # how long a fetched secret set is reused
```

`path_template` is the KV v2 API path, so it includes the mount's `data/` segment. It must contain `{name}` and exactly one of `{pool}` or `{tag}`. Secret sets are cached per scope and set for `cache_ttl`; errors are never cached.

The configuration is read once at startup, so run `systemctl restart pve-imds` after changing it. The service runs as a dynamic user, so the file must be readable by other users (the default `0644` is fine; it holds no secrets) or by the `pve-imds-token` group. To use environment variables instead, add them in a drop-in with `systemctl edit pve-imds`:

```ini
[Service]
Environment=PVE_IMDS_SECRETS_ENABLED=true
Environment=PVE_IMDS_SECRETS_ADDRESS=https://openbao.example.com:8200
```

## How it works

I think the EC2 IMDS approach (now shared by other hypervisors and clouds) is extremely elegant. A VM can make a request to `http://169.254.169.254` and retrieve information about itself, like looking in a mirror. The VM doesn't even need a valid DHCP lease because `169.254.169.254` is a [link-local IP address](https://en.wikipedia.org/wiki/Link-local_address) and the packets (at least in the case of `pve-imds`) never leave the hypervisor.

This does make the solution slightly more complicated. To provide a strong guarantee that a VM will be able to retrieve its identity *and only its identity*, the hypervisor must be able to intercept and directly respond to packets leaving the VM destined for `169.264.169.254`. Doing this at line rate speeds is challenging. In the cloud, hypervisors (I'm guessing) offload this interception to hardware like [AWS Nitro](https://aws.amazon.com/ec2/nitro/). In the case of `pve-imds`, we use XDP ([eXpress Data Path](https://en.wikipedia.org/wiki/Express_Data_Path)) to intercept packets as soon as they hit the VM's `tap` interface before they hit the rest of the kernel networking stack (or whatever, I'm not an expert). I've been able to maintain full line rate from a VM bridged to a 25GbE network with this approach.

XDP intercepts the full Ethernet frame, so we use the [gVisor userspace TCP stack](gvisor.dev/gvisor/pkg/tcpip/stack) to handle the path between the raw `AF_XDP` socket and the VM-specific HTTP handler. An in-memory metadata cache parses Proxmox VM configuration files for updates, refreshing as necessary via [fsnotify](https://github.com/fsnotify/fsnotify).

## Known limitations

My goal with releasing this is to hopefully improve it with community feedback. I find it useful in my homelab. There is absolutely no warranty, express or implied, that it is suitable in its current or future form for any use case of any import. Use at your own risk.

I have only tested this with VMs running on Proxmox 9 using `virtio` interfaces (though I don't think the interface type matters). This *will not work* with VMs using SR-IOV, unless the VM has a secondary interface with a link-local address.

## Future work

- hardware offload using [ASAP<sup>2</sup> direct](https://docs.nvidia.com/networking/display/mlnxofedv24103250lts/ovs+offload+using+asap%C2%B2+direct)

## AI disclosure

This was not vibe-coded. I used Claude Code to author most of the code here, but by specifying exactly the architecture and approach that I personally designed as an experienced software and infrastructure engineer, and with thorough review. I could have written all of this on my own (and I did for the prototype), but this approach saved me a fuckton of time and enabled me to do things like write conformance tests that test `pve-imds` against `cloud-init`.
