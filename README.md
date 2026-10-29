# TrueNAS (Hisho add-on)

## What it does

Read only, for TrueNAS SCALE / Community Edition 25.04 or newer: each pool's health, space and last
scrub, disk temperatures, TrueNAS's own alerts and the SMB shares. It alerts when a pool degrades or
fills up, a disk runs hot, or a share you depend on goes away. It calls only read methods over
TrueNAS's websocket API.

## What it needs

- You need:
  - TrueNAS SCALE / Community Edition 25.04 or newer
  - Its admin login once, so Hisho can make its own read-only user and API key; or an API key made by hand
- Runs on: the Core machine, inside Hisho Core
- One entry per TrueNAS, each with:
  - `url` (str, required)
  - `api_key` (password, kept as a local secret, required)
  - `fingerprint` (str, optional)
  - `watch_shares` (str, optional)
  - `disk_warn_c` (int, optional)
  - `note` (str, optional)

## How to install

On the dashboard: **Add-ons > Store > TrueNAS > Install**. Or from a terminal:

```bash
hisho addon install truenas
```

Hisho takes the newest version from this repository and turns it on inside Hisho Core. Updates show as **Update
available** on its Store card; **Roll back** returns to the version before.

## How to use

Its card shows any pool that is degraded or filling, a hot disk or a missing share. Its page (**Add-ons > TrueNAS**) has each pool, disk and share. It only reads.

## Settings

Add a TrueNAS on its page (**Add-ons > TrueNAS**). **Found on your network** lists the TrueNAS it sees
(their sign-in page); press **Use this** (or type the address), give it a short name, type an admin login
(e.g. `truenas_admin`) and its password, and press **Sign in once**. Hisho signs in once over https (the
certificate is pinned first) and makes:

- user `hisho`: no password, no SMB access, in TrueNAS's built-in Read-only Administrators group,
- an API key `hisho` for it (`hisho-<date>` if that name is taken).

A TrueNAS API key can do whatever its user can, so this key can only read. If this TrueNAS has no
Read-only Administrators group, or the read-only key can't read pools, the key is made for the admin you
signed in with instead and the page says so (Hisho still only calls read methods with it). The admin
password is used once and not kept; the key is kept only on the Core machine (`~/.hisho-secrets.env`).

Or open **+ add by filling in every field yourself**: in TrueNAS click the user icon (top right) > My API
Keys > Add, name it "hisho"; it shows the key once. Paste it, or save it as a secret (e.g.
`TRUENAS_CE_API_KEY`) and give its name. Add the shares other machines depend on to "Shares to watch".
Entries are kept in `~/Hisho/System/Config/Addons/truenas.yaml`.

## How to remove

**Add-ons > Store > TrueNAS > Remove**, or `hisho addon remove truenas`. Its card and page go away; your settings stay in `~/Hisho/System/Config/Addons/truenas.yaml`, so installing it again picks up where you left off.

## License

Source-available under the [PolyForm Shield License 1.0.0](LICENSE.md): free to use, change and share,
for any purpose except offering a product that competes with Hisho (reselling it, for example).
