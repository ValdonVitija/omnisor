# Model and software overrides

Place profiles here only when a device model/OS requires different identity, access policy, modules or
mappings. Extend `cisco-ios-snmp`; override changed fields without copying its
Collector config. Register the profile in `collection/catalog.yaml` and record
exact validation evidence in `docs/product/COMPATIBILITY.md`.

`iosvl2/profile.yaml` revision 2 extends the common system/interface profile and
adds the generated `cisco_ios_legacy` module. On the 20190423 image, legacy
`avgBusy1`, `freeMem` and `processorRam` provide CPU and processor memory readings;
the newer process/memory-pool MIB trees are absent. Both native macOS collection
processes and all 66 normalized series were validated on 2026-11-14. Site-specific
SNMP access and the local lab endpoint live in the saved device record. This is
exact-image evidence, not a universal IOSvL2 compatibility claim.
