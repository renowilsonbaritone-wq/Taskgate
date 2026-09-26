# TaskGate shared service 1.6.0

A central service for separate TaskGate accounts, private task sessions, recipient-bound invitations, viewer/approver permissions, and progress sync. Intended for a small trusted group. The desktop continues enforcing blocks and cutoff locally during outages.

Nothing in this package creates a paid account or deploys a public server automatically.

## Recommended: Render

Use a **paid web service with a persistent disk**, one instance. Render supplies an HTTPS `onrender.com` address; a custom domain is optional. Check [current pricing](https://render.com/pricing) before deployment. Free ephemeral storage cannot retain this SQLite database through restarts/deploys. See [persistent disk documentation](https://render.com/docs/disks) and [Blueprint reference](https://render.com/docs/blueprint-spec).

1. Extract this server archive. Create a GitHub or GitLab repository and upload **these server files at the repository root**, including `render.yaml`, `requirements.txt`, `server.py`, `wsgi.py`, and `manage.py`. Do not upload private keys, desktop credentials, databases, or `.env` files. No repository has been created for you.
2. Create/sign into Render, connect that repository, choose **New → Blueprint**, and select it. Review the paid service/storage charges before deploying.
3. The Blueprint creates one `0.5c-512mb` service and a 1 GB disk mounted at `/var/data`. It generates `TASKGATE_JOIN_CODE` as a secret environment variable. Keep that variable secret; share its value only with people allowed to register accounts. Retrieve it from the service's Environment settings.
4. Wait for the health check `/v1/health` to return `{"ok":true,"api":1}` at your assigned HTTPS URL.
5. Give group members the server base address and registration code. They use **People → Create account** in TaskGate 1.6.0. Do not append `/v1/health` or any other path to the address entered into the app.
6. Try a short session with two accounts and test invitation, submission, approval, and revocation before relying on a long focus session.

The Blueprint pins Gunicorn 26.2.0 and Python 3.12.12. It has one worker with eight threads; keep one worker and one instance because in-process rate limits and SQLite storage are designed for that topology. Before substantially growing the group, move storage to a managed database and add load/security testing and stronger operational monitoring. Do not enable horizontal autoscaling for this SQLite deployment.

## Alternative: your own VPS

The supplied `Dockerfile`, `compose.yaml`, and `Caddyfile` run Gunicorn behind Caddy HTTPS. You need a Linux server with Docker Compose, a domain pointing at it, and incoming TCP ports 80/443 allowed. Do not expose port 8787 publicly.

Create `.env` beside `compose.yaml` with a real hostname and a randomly generated registration code of at least 16 characters:

```text
TASKGATE_DOMAIN=taskgate.your-domain.example
TASKGATE_JOIN_CODE=replace-with-a-long-random-secret
```

Then run `docker compose up -d --build`. This requires internet access to retrieve container images and dependencies. The named `taskgate-data` volume persists the database. Caddy stores its certificate state in its own volumes. The supplied Docker deployment has not been run against a live host in this workspace.

## Local developer use

Python 3.10+ is enough for the API logic. For a local-only demonstration, set `TASKGATE_JOIN_CODE` and run `python3 server.py --database demo.sqlite3`. It binds `127.0.0.1:8787`; the app permits HTTP only for localhost. The standard-library development server is not the public deployment entry point.

Production uses `pip install -r requirements.txt` followed by:

```sh
gunicorn --bind 0.0.0.0:8787 --workers 1 --threads 8 --timeout 30 'wsgi:application()'
```

Set `TASKGATE_DATABASE` to a persistent writable database path and `TASKGATE_JOIN_CODE` to a random secret. Put an HTTPS reverse proxy in front. Trust no forwarded IP headers unless you deliberately configure a trusted proxy; this application does not use them. Behind a proxy, registration/login throttling may apply to the whole group (30 attempts per five minutes), so stagger group signup if necessary.

## Backups and recovery

Create a consistent SQLite backup with the included utility from the service shell:

```sh
python3 manage.py backup /var/data/taskgate-backup.sqlite3
```

It refuses to overwrite an existing destination. Use a distinct filename for each backup, then download/store a protected copy outside the server. Back up regularly, especially before deployment. Backups contain tasks and credential hashes; restrict access. Raw copying of only the main SQLite file while it is live can miss WAL data.

To restore, stop the service first, preserve the current database and its `-wal`/`-shm` files separately, replace the database with a consistent backup at `TASKGATE_DATABASE`, remove the old WAL/SHM files from the live path, restore ownership for the service user, and restart. Test restoration using a separate service before an emergency. Do not copy old WAL files alongside a restored backup.

There is no email password recovery. A host administrator can reset a user's password interactively:

```sh
python3 manage.py reset-password username
```

This also revokes all that user's access tokens; they must sign in again on each device. Never put passwords in command-line arguments or source control. Changing the registration code prevents use of the old code for new registrations but does not revoke existing accounts.

## Privacy and limits

Users see only their own sessions or sessions to which they have accepted an invitation. Invitations are specific to a username, expire in seven days, and are single-use. Revocation is enforced on every subsequent read and approval. Owners cannot approve their own remote tasks. Viewers cannot approve. Remote completion is accepted only from an invited approver after submission. Any one approver is sufficient; this is not unanimous approval.

The server stores task text, task states, cutoff, timestamps, approval attribution, account records, and session memberships. No website/app/keyword rules or browsing history are sent. TLS protects data in transit, but this is not end-to-end encryption: the service host can read the database. Keep the hosting account secure.

The first version has no GUI data-deletion or automated retention policy; the host is responsible for retention and requested removal. It allows up to 100 tasks and 100 participants per session, 1,000 sessions per owner, and 10,000 registered accounts as defensive upper bounds, not a tested capacity claim. The app shows the latest 100 accessible sessions. Add monitoring and a support/recovery process before broader public use.

API health: `GET /v1/health`. API routes are under `/v1`; other pages are intentionally absent. The hosted service does not deliver desktop software updates, emails, or notifications.
