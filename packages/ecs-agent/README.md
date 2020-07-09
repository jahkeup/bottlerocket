# ecs-agent

The ecs-agent package in Bottlerocket provides the ECS agent and a systemd unit
that sets up necessary configuration on the host.

This README is temporary and is meant to track the known issues and remaining
work items for the ECS agent.

## Known issues

* CNI plugins are not yet packaged - This means that awsvpc mode and AppMesh
  are both currently unsupported.
* Logging is currently set to `debug` to assist with development.
* The systemd unit contains many `ExecStartPre`/`ExecStartPost` commands, with
  little explanation or infrastructure.  One `ExecStopPost` command depends on
  `/bin/sh`, which is not available in Bottlerocket or compatible with our
  goals for Bottlerocket.