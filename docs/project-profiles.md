# Project Guard Profiles

## PacketSafari

Use the default profile for host-side development commands:

```sh
guard pnpm --dir frontend run dev
guard python scripts/some_tool.py
```

Use the Docker profile only for Docker commands:

```sh
guard --profile docker docker compose -f docker-compose-dev.yml config
guard --profile docker docker compose -f docker-compose-dev.yml up
```

The Docker profile opens the Docker Desktop socket. Treat that as a high
privilege profile: Docker can mount host paths and can run containers that reach
the network even when the local guard policy says `net=none`.

PacketSafari currently mounts `~/packetsafari-data` into several dev services.
That means Docker-side isolation depends on the compose file, not only on
guard.
Prefer narrower bind mounts and `:ro` for inputs whenever the service does not
need to write.

## Wireshark

Use the default profile for local build and test commands:

```sh
guard cmake -S . -B build-anoncap-min
guard cmake --build build-anoncap-min
guard python3 tools/some_test.py
```

The Wireshark profile denies reads from `~`, `/Volumes`, `/Applications`,
`/cores`, and `/home`, then re-opens the Wireshark checkout, the guard runtime
directory, and the related local anoncap guidance paths from `~/code/waveanalyzer`.

## On-Prem Bootstrap

The on-prem profile protects host home and volume reads, and denies writes to
`keys/`, `secrets/`, and common key file names. Real long-lived keys should not
live inside a project directory that is opened with `allowRead`, because
guard's
read carve-out model re-opens the allowed project subtree.
