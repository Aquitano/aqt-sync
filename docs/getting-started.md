# Your first sync

You need the aqt client, an aqt server URL, and an account on that server.
Installing the client does not create a server or an account.

## Install and choose a server

Follow the [install instructions](../README.md#install), then open a new terminal and run:

```sh
aqt --version
```

If the command is not found, add the install directory to your PATH. The default is
`~/.local/bin` on macOS and Linux, or `%LOCALAPPDATA%\Programs\aqt` on Windows.

Ask your server operator for its HTTPS URL and an invite token if registration is
restricted. To run your own server, follow the [deployment guide](deploy.md).
The `https://aqt.example.com` URL below is a placeholder. Replace it with your server.

For a local trial, install the server binary too and run `aqt-server` in another
terminal. Use `http://localhost:8080` as the URL. Keep that terminal running.

## Create an account once

On your first device:

```sh
aqt --server https://aqt.example.com signup --email you@example.com
```

If your server requires an invitation, set `AQT_INVITE_TOKEN` in your environment
before running signup, or add `--invite` with the token.

Choose a passphrase and save it in a password manager. You need the same server URL,
email, and passphrase to recover your files on a new device. There is no passphrase
reset. The server stores your encryption key wrapped under that passphrase.

Signup signs you in and saves the server URL. You do not need to run login next or
repeat `--server` for everyday commands. Check the saved account with:

```sh
aqt whoami
```

Already have an account? Use `login` instead of `signup`, with the same server URL
and email. On a configured device, `aqt login` reuses both and asks for your
passphrase to unlock the session.

## Sync a small folder

Start with a test folder so you can check the full process before adding your files.
These commands work in a shell or PowerShell:

```sh
mkdir aqt-trial
```

Create a text file inside `aqt-trial`, then run:

```sh
aqt init ./aqt-trial
```

Init creates the folder's tracking state and a private resource on the server. It
does not upload your files. Review `aqt-trial/.aqtignore` to choose what to exclude.
If the folder contains a Git repository, aqt asks whether to include `.git`.

Preview the first upload, then sync:

```sh
aqt sync ./aqt-trial --dry-run
aqt sync ./aqt-trial
aqt status ./aqt-trial
```

Status should report no pending changes after a successful sync. Sync works in both
directions: edits and deletions propagate between devices. By default, conflicting
edits stop the sync for you to review.

`aqt sync` runs once. Run it after changes, or keep `aqt watch ./aqt-trial` running
for automatic sync. Use Ctrl+C to stop watching.

## Recover a copy

On another device, install aqt and sign in:

```sh
aqt --server https://aqt.example.com login --email you@example.com
aqt ls --kind folder
```

Use the folder's ID from that list to download it into a new directory. Replace
`FOLDER_ID` with the actual ID:

```sh
aqt clone FOLDER_ID ./aqt-recovered
```

Open the restored text file and compare it with the original. You can also run this
clone on your first device to check recovery before setting up another device.
The clone is tracked, so later `aqt sync ./aqt-recovered` calls exchange changes.
Use `clone` for an existing remote folder; `init` creates a separate remote folder.

For a named recovery point, run these commands from inside a tracked folder:

```sh
aqt checkpoint before-changes
aqt restore before-changes --out ../aqt-checkpoint-copy
```

Restore writes a separate copy by default. In-place restore requires `--in-place`.
Snapshots live on the same server as the synced files. Keep
[server backups](deploy.md#backup-and-restore) for recovery if that server is lost.

## When something stops you

| What you see | What to do |
| --- | --- |
| No profile found | Use `signup` for a new account or `login` for an existing one. Include your server URL. |
| Connection refused on localhost | Start your local server, or use `--server` with your actual server URL. |
| Invite required | Ask your server operator for an invite token. |
| Could not unlock | Check the server URL, email, and passphrase. Use `signup` if you have never created an account there. |
| No unlocked session | Run `aqt login`. It reuses the saved email and server. |
| Folder is not tracked | Use `init` to start a new folder, or `clone` to download an existing one. |
| Sync conflicts | Run `aqt diff` in the folder to inspect changes. `aqt sync --conflicts=copy` keeps the local version and saves the remote version beside it. |

Run `aqt --help` for commands grouped by task, or `aqt <command> --help` for options.
