<!--[metadata]>
+++
title = "swarm join"
description = "The swarm join command description and usage"
keywords = ["swarm, join"]
advisory = "rc"
[menu.main]
parent = "smn_cli"
+++
<![end-metadata]-->

# swarm join

```markdown
Usage:  docker swarm join [OPTIONS] HOST:PORT

Join a Swarm as a node and/or manager

Options:
      --advertise-addr value   Advertised address (format: <ip|hostname|interface>[:port])
      --ca-hash string         Hash of the Root Certificate Authority certificate used for trusted join
      --help                   Print usage
      --listen-addr value      Listen address
      --manager                Try joining as a manager.
      --secret string          Secret for node acceptance
```

Join a node to a Swarm cluster. If the `--manager` flag is specified, the docker engine
targeted by this command becomes a `manager`. If it is not specified, it becomes a `worker`.

### Join a node to swarm as a manager

```bash
$ docker swarm join --secret 4ao565v9jsuogtq5t8s379ulb --manager 192.168.99.121:2377
This node joined a Swarm as a manager.
$ docker node ls
ID                           HOSTNAME  MEMBERSHIP  STATUS  AVAILABILITY  MANAGER STATUS         LEADER
dkp8vy1dq1kxleu9g4u78tlag *  manager2  Accepted    Ready   Active        Reachable
dvfxp4zseq4s0rih1selh0d20    manager1  Accepted    Ready   Active        Reachable              Yes
```

### Join a node to swarm as a worker

```bash
$ docker swarm join --secret 4ao565v9jsuogtq5t8s379ulb 192.168.99.121:2377
This node joined a Swarm as a worker.
$ docker node ls
ID                           HOSTNAME  MEMBERSHIP  STATUS  AVAILABILITY  MANAGER STATUS         LEADER
7ln70fl22uw2dvjn2ft53m3q5    worker2   Accepted    Ready   Active
dkp8vy1dq1kxleu9g4u78tlag    worker1   Accepted    Ready   Active        Reachable
dvfxp4zseq4s0rih1selh0d20 *  manager1  Accepted    Ready   Active        Reachable              Yes
```

### `--ca-hash`

Hash of the Root Certificate Authority certificate used for trusted join.

### `--listen-addr value`

If the node is a manager, it will listen for inbound Swarm manager traffic on this
address. The default is to listen on 0.0.0.0:2377. It is also possible to specify a
network interface to listen on that interface's address; for example `--listen-addr eth0:2377`.

Specifying a port is optional. If the value is a bare IP address, hostname, or interface
name, the default port 2377 will be used.

This flag is generally not necessary when joining an existing swarm.

### `--advertise-addr value`

This flag specifies the address that will be advertised to other members of the
swarm for API access. If unspecified, Docker will check if the system has a
single IP address, and use that IP address with with the listening port (see
`--listen-addr`). If the system has multiple IP addresses, `--advertise-addr`
must be specified so that the correct address is chosen for inter-manager
communication and overlay networking.

It is also possible to specify a network interface to advertise that interface's address;
for example `--advertise-addr eth0:2377`.

Specifying a port is optional. If the value is a bare IP address, hostname, or interface
name, the default port 2377 will be used.

This flag is generally not necessary when joining an existing swarm.

### `--manager`

Joins the node as a manager

### `--secret string`

Secret value required for nodes to join the swarm


## Related information

* [swarm init](swarm_init.md)
* [swarm leave](swarm_leave.md)
* [swarm update](swarm_update.md)
