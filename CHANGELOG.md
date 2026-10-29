# Changelog

## 0.2.0

- Found on your network: the page lists the TrueNAS it sees (their sign-in page), with Use this.
- Sign in once: type an admin login once and Hisho makes its own user hisho (no password, no SMB, Read-only
  Administrators group) and an API key for it, over the pinned websocket API; the password is not kept. An existing
  user is reused and a key name in use gets a dated name. Without a read-only group (or if that key can't read) the
  key is the admin's, and the page says so. Two-factor admins are told to make the key by hand.
- Setup help says to use Sign in once, and that a key can do whatever its user can.

## 0.1.2

- Every field on its setup form says in plain words what it is, and links to where to get it (addon.yaml `help:`, shown by Hisho's dashboard).

## 0.1.1

- README says what you need (addon.yaml you_need) and how to use it; the README check requires both.

## 0.1.0

- Moved out of Hisho into its own repository (hisho-addon-truenas); installed from the add-on store.
- Per-disk temperature alerts.
