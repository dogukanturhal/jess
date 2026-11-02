# SSH through jess without a VPN (`jessctl connect --stdio`)

`jessctl connect --stdio` brokers one session to a jess target and pipes it to
stdin/stdout, so OpenSSH can use it as a `ProxyCommand`. Nothing but session
bytes is written to stdout (login URL and errors go to stderr). Approval, MFA
and grant checks are identical to `--listen`.

```
# ~/.ssh/config
Host gitlab-ssh node-cp-01
    ProxyCommand jessctl connect --stdio --controller controller.internal.example.com:7101 --grant <grant-id> %n
```

`%n` is the original host name typed on the command line, so name the `Host`
entry after the jess **target id** (as listed in the jess target catalog), or
hard-code the id: `... jessctl connect --stdio <target-id> --controller ...`.
Use `--grant` with a literal grant id (ssh does not expand environment
variables in ProxyCommand; `JESS_GRANT`, `JESS_CONTROLLER`, `JESS_TOKEN` are
read from the environment if the flags are omitted, so prefer
`JESS_GRANT=<id> ssh host`).

Simplest form:

```
export JESS_CONTROLLER=controller.internal.example.com:7101 JESS_GRANT=<grant-id>
# ~/.ssh/config:  ProxyCommand jessctl connect --stdio %n
ssh node-cp-01
```
