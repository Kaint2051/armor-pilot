# Third-party notices

## vArmor

ArmorPilot integrates with the open-source vArmor project through its
Kubernetes Custom Resource Definitions and APIs.

- Project: <https://github.com/bytedance/vArmor>
- License: Apache License 2.0, except for components identified separately by
  the upstream project
- Copyright: The vArmor Authors

The vArmor eBPF repository is licensed separately under GPL-2.0. ArmorPilot's
container image does not build or bundle that upstream eBPF source; it connects
to an independently installed vArmor deployment.

The names vArmor and ByteDance belong to their respective owners. Use of those
names in ArmorPilot documentation describes compatibility and origin only.
ArmorPilot is not affiliated with, endorsed by, or an official distribution of
the vArmor project or ByteDance.

## Bundled dependencies

Python and JavaScript dependencies retain their respective licenses. Review
`requirements.txt`, `package-lock.json`, and the corresponding package
metadata when preparing a distribution or software bill of materials.

