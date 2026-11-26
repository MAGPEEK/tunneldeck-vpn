# Lost admin password

TunnelDeck has a single admin account. If its password is lost, you reset the account and create a new one. This guide explains what a reset changes and the two ways to start it.

## What a reset does

A reset:

- removes the admin account (username and password hash),
- ends every session, including remembered "Stay signed in" sessions on all devices.

It keeps everything else: VPN profiles and their secrets, firewall rules, settings, certificates and remote-access configuration. A connected tunnel stays connected.

The next visit to the web UI shows the setup page, where you create a new admin account.

## Method A: command in the container

Run the command inside the running container:

```sh
docker exec tunneldeck tunneldeck reset-admin
```

`tunneldeck` is the container name from our compose files (`docker-compose.yml`, `deploy/synology/docker-compose.yml`). If you named the container differently, find it with:

```sh
docker ps --format '{{.Names}}\t{{.Image}}'
```

### On a Synology NAS

- **Over SSH:** sign in to the NAS and run `sudo docker exec tunneldeck tunneldeck reset-admin`.
- **In Container Manager:** Container > tunneldeck > Details > Terminal > Create, choose `sh` as the command, then type `tunneldeck reset-admin` in the new terminal. The exact menu names depend on the DSM version; check them on your NAS.

### Expected output

While the server is running, the command asks it over its local control socket to do the reset, and the log line says:

```
admin account removed by the running server; open the web UI to run setup again
```

If no server is running (for example in a stopped container started only for this command), the command edits the data directory directly:

```
admin account removed (no server was running); setup is offered at the next start
```

Any other result is an error message starting with `reset admin:`.

## Method B: environment variable, no shell needed

Use this when you cannot open a shell in the container.

1. Add the variable to the container's environment, in the compose file:

   ```yaml
   environment:
     TUNNELDECK_RESET_ADMIN: "1"
   ```

   or on a Synology in the project's YAML (Container Manager > Project > tunneldeck) or the container's environment settings.
2. Recreate the container (`docker compose up -d`, or Project > Action > Build in Container Manager).
3. Open the web UI and set up the new admin account.
4. **Remove the variable again** and recreate the container once more.

While the variable is set, the server removes the admin account and all sessions **at every start**, and logs this warning each time:

```
TUNNELDECK_RESET_ADMIN is set: the admin account is removed at every start until the variable is removed
```

So if you forget step 4, the next restart (an update, a NAS reboot) deletes the account you just created and shows the setup page again, open to anyone who reaches the UI first.

## Afterwards

- Create the new admin account on the setup page. The password must have at least 12 characters.
- If you use remote access over HTTPS, check on the **System** page that it still works; its configuration and certificate are unchanged.
- You do not need "Sign out everywhere": the reset already ended all sessions on every device.

## Security note

Anyone with access to the Docker host (SSH, `docker` commands, Container Manager) or to the data directory can reset the admin account and take over the UI. Protect SSH and DSM access with strong passwords and two-factor authentication, and do not expose them to the internet.
