# devnull-ssh-server

An SSH server that lets anyone commit to [dev-null.sh](https://dev-null.sh) with their own SSH key:

```sh
ssh -A <host> commit 'Hello world!'
echo 'Hello world!' | ssh -A <host> commit
ssh -A <host> commit --reply 0be0130 'Agreed!'
```

`-A` forwards your SSH agent. To leave it out, put this in `~/.ssh/config`:

```
Host devnull
  HostName <host>
  Port 2222
  ForwardAgent yes
```

Then `ssh devnull commit 'Hello world!'` works.

## How it works

dev-null.sh has no login. A commit is a message signed with `ssh-keygen -Y sign` in the `devnull-commit` namespace,
and dev-null.sh checks the signature against the keys GitHub publishes for you
([the official commit script](https://dev-null.sh/commit) does the same thing on your machine). This server does it
for you over SSH, in Go, without running any other program:

1. You log in with any key. The server accepts every key, because a key here can only sign a commit, and dev-null.sh
   decides whose key it is.
2. It lists the Ed25519 and RSA keys of **your forwarded agent** and asks dev-null.sh's `/api/cli/key-lookups` which
   one is on your GitHub account, offering the key you logged in with first. This is what the commit script does, and
   it matters: ssh logs in with the first key your agent holds, which may not be your GitHub key.
3. It builds the payload `<unix time>\n<nonce>\n<reply to>\n<message>`, as the commit script does.
4. It asks your agent to sign the payload with that key, in the
   [SSHSIG](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig) format (`rsa-sha2-512` for RSA),
   checks the signature, and closes the agent channel. It talks to your agent over the SSH connection itself, so no
   agent socket is ever created on the server.
5. It posts the commit to `/api/cli/commits` and prints dev-null.sh's answer.

The server never sees a private key, and keeps nothing except its own host key.

## What forwarding your agent means

While you are connected, a forwarded agent will sign **anything** the server asks it to, not only dev-null.sh commits.
The `devnull-commit` namespace limits what dev-null.sh accepts; it does not limit what your agent signs. Only forward
your agent to a server you trust. To be asked before every signature, add your key with `ssh-add -c`. Or forward an
agent that holds only your dev-null.sh key: `ForwardAgent ~/.ssh/devnull-agent.sock` (OpenSSH 8.2 or newer) forwards
that agent instead of your usual one.

## Running it

| Variable               | Default                     | What it is                                         |
| ---------------------- | --------------------------- | -------------------------------------------------- |
| `DEVNULL_SSH_LISTEN`   | `:2222`                     | Address to listen on                               |
| `DEVNULL_URL`          | `https://dev-null.sh`       | Where commits go (https, or http to localhost)     |
| `DEVNULL_SSH_HOST_KEY` | `data/ssh_host_ed25519_key` | Host key; an Ed25519 key is made on the first start |
| `DEVNULL_SSH_NAME`     | `<host>`                    | How the server names itself in its usage text      |

```sh
go run .
```

Or with Docker, keeping the host key on a volume, so clients don't see it change:

```sh
docker build -t devnull-ssh .
docker run -p 2222:2222 -v devnull-ssh:/data -e DEVNULL_SSH_NAME=<host> devnull-ssh
```

The image runs as the distroless `nonroot` user (uid 65532). A named volume gets the right owner by itself; for a bind
mount, `chown 65532` the directory first, or the server can't write its host key.

The log prints the host key's fingerprint on start, for users to check against, and one line per commit with the
client's address and key fingerprint. The server takes 64 connections at a time, 4 per client address. Behind a proxy
that hides client addresses, the per-address limit applies to the proxy.

## Development

```sh
go test ./...
```

The tests run a real SSH server and client in process, with a forwarded in-memory agent and a fake dev-null.sh that
verifies signatures the way dev-null.sh does. One test also checks the signatures with OpenSSH's own
`ssh-keygen -Y check-novalidate`, when it is installed.
