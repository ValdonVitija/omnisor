# Upstream SNMP modules

Selected unchanged module blocks from [snmp_exporter v0.29.0 snmp.yml](https://github.com/prometheus/snmp_exporter/blob/v0.29.0/snmp.yml). Only the file-level `modules:` wrapper and provenance comment were added. No default authentication is bundled.

Upstream SHA-256: `42324a90487757b3aadbb7bbf544d504bcbb6b6ccd09136f36543024fa02d33f`. Licensed under Apache-2.0; see LICENSE and NOTICE.

Regenerate device-specific OID changes with the upstream MIB generator. Do not edit generated metric definitions by hand. Pin generator and exporter to the same version.

## Generated IOSvL2 legacy module

`cisco_ios_legacy.yaml` is generated with the upstream v0.29.0 generator from
Cisco's OLD-CISCO-CPU-MIB, OLD-CISCO-MEMORY-MIB and OLD-CISCO-CHASSIS-MIB. It is
separate from the unchanged upstream module blocks above. `avgBusy1` is a one-minute
exponentially-decayed CPU average; `freeMem` reports free bytes; `processorRam`
reports RAM bytes available to CPU. Only these three read-only scalars are requested.

Generation input, exact Cisco source revision/URLs/SHA-256 checksums and the
upstream generator source archive hash are in `generator/cisco-iosvl2/`. MIB source
files are fetched for generation and are not vendored. Build the upstream generator
at tag v0.29.0 as described in its README, then reproduce with:

```sh
python3 collection/exporters/snmp/v0.29.0/generator/cisco-iosvl2/generate.py \
  --generator /path/to/v0.29.0/generator
```

The generated module was accepted by the real v0.29.0 macOS exporter and delivered
CPU/processor memory measurements through the Collector and OTLP receiver on
2026-11-14. Runtime session authentication is assembled separately; no default
community is included in this module or the generation input.
