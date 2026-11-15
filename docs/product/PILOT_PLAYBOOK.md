# Discovery and pilot playbook

Status: historical recurring-assessment/web pilot proposal. The
[desktop roadmap](../../ROADMAP.md) and [desktop architecture](ARCHITECTURE.md)
now define the active scope. Scheduled-team and paid-pilot gates below are not
desktop release requirements. Reuse the compatibility, findings, secret handling,
and failure scenarios where applicable; desktop gates are in the current roadmap.

Use this playbook for [M0, M2, and M3](../../ROADMAP.md#milestones-and-acceptance-gates).
These are templates and acceptance criteria. Interviews, recruitment, product
pilots, and paid commitments have not been recorded by creating these documents.

## Discovery: five internal network teams

Speak with engineers who perform health reviews and, where possible, the person
who can approve a purchase. Ask about a recent actual review before presenting
the proposed product.

1. When did you last review operational health across a group of devices? What
   triggered it, how often does it happen, and what happened afterward?
2. Walk through the tools, commands, manual steps, and people involved. How much
   setup, collection, review, and report preparation time did it take?
3. Which existing monitoring or automation tools already solve parts of this job?
   Where do you still need manual work or lack confidence in the results?
4. What made a finding useful? Which expected conditions or false positives caused
   noise? Describe a missed issue or a report that helped make a decision.
5. Which device models, software versions, fleet sizes, network segments, and
   authentication/host-trust requirements would an assessment need to cover?
6. Who uses the report, what evidence do they need, and what can be stored or
   exported? Which deployment, retention, or access constraints apply?
7. What would make a first pilot successful, and could you provide an appropriate
   lab or device scope for validation?
8. Would repeated results need shared review, ownership, acknowledgements, policy
   reuse, or delivery into another tool? Ask for a concrete example.
9. Who owns the budget and buying process? What alternatives would this replace
   or complement? What would justify an annual team subscription?
10. Agree a possible next step: another interview, a bounded pilot, or no further
    action. Record the reason rather than treating interest as a commitment.

Record each interview using this template. Keep identifying information and raw
network evidence in access-controlled storage; use anonymized references here.

```text
Interview reference / date / interviewer:
Team context and participant roles:
Recent review example, frequency, and current workflow:
Current tools and unmet gap:
Manual effort baseline and source of estimate:
Useful findings, false positives, and missed issues:
Fleet size, models, software, and validation access:
Deployment, access, evidence, and retention constraints:
Required outcome and pilot success criteria:
Buyer, budget process, alternatives, and pricing feedback:
Next step, commitment level, and private evidence reference:
Contradictions or reasons the proposed product may not fit:
```

| Interview slot | Evidence reference | Outcome |
| --- | --- | --- |
| I01 | Pending | Not interviewed |
| I02 | Pending | Not interviewed |
| I03 | Pending | Not interviewed |
| I04 | Pending | Not interviewed |
| I05 | Pending | Not interviewed |

**M0 review:** Summarize the repeated job, gap, accessible device families, and
deployment constraints. Identify three willing pilot teams and unresolved
assumptions. Revise the offer if the evidence does not support recurring use.

## Pilot setup and run records

Before each pilot, record an anonymized team reference, technical contact and
buyer reference, agreed device scope, tested compatibility entries, cadence,
deployment environment, expected conditions, retention policy, and success
criteria. Agree how results will be reviewed and how to record feedback.

Run at least four scheduled assessments per team. A useful clean result can count
as verification; document why the engineer trusted it. Collection success alone
does not establish that a report was useful.

```text
Pilot/team reference and assessment/run ID:
Omnisor revision, deployment resources, and compatibility references:
Scope, check/expected-condition revision, trigger, and scheduled time/timezone:
Start/completion time, duration, and interruptions:
Devices attempted/completed/partial/failed/uncollected:
Unsupported or unknown checks, affected devices, and causes:
Findings reviewed, useful findings, and reviewer-confirmed false positives:
Report review time and comparison with the manual baseline:
Action taken or useful verification, with engineer feedback:
Setup/support time, resource usage, device load, and storage growth:
Private evidence reference, problems, and next step:
```

Use the same unit of work when comparing manual and Omnisor effort. Record raw
counts and denominators for false positives and collection completion. Distinguish
actively used reports from assessments that merely ran unattended.

| Pilot slot | Setup effort | Scheduled runs completed / minimum | Continue using? | Evidence |
| --- | --- | --- | --- | --- |
| P01 | Pending | 0 / 4 | Unknown | Pending |
| P02 | Pending | 0 / 4 | Unknown | Pending |
| P03 | Pending | 0 / 4 | Unknown | Pending |

**M2 review:** All three teams complete at least four scheduled assessments each;
at least two explicitly choose to continue. Summarize useful findings,
false-positive feedback, review time, onboarding burden, and actions/verification.
Record failed gates and the changes needed before repeating the pilot.

## Engineering acceptance

Record the code revision, environment, test command or manual steps, result, and
evidence reference for each applicable scenario.

| Area | Acceptance scenarios |
| --- | --- |
| Coverage | Replay fixtures and synthetic SSH checks pass; real-device checks have exact model/software records and sanitized evidence |
| Findings | Healthy, unhealthy, expected, unknown, and uncollected observations remain distinguishable; missing data cannot appear as recovery |
| Partial failure | Unreachable device, authentication failure, rejected command, malformed output, timeout, and disconnect leave useful completed work visible |
| Host trust | Trusted host connects; unknown host requires explicit trust; changed host key fails verification |
| Credentials/evidence | Secrets are absent from debug logs, errors, stored assessment results, UI evidence, and exports |
| Web access | Unauthenticated access to inventory/results/exports is rejected; state changes enforce the chosen session authorization and request protections |
| Scheduling | Run-now and scheduled runs work; restart retains schedules, marks interrupted work, and prevents overlap or a catch-up burst |
| Persistence | History survives restart; backup/restore and schema upgrades retain valid records; retention removes records/evidence consistently |
| Comparison/export | Stable identities support previous-run comparisons; changed scope or missing coverage is visible; reports preserve source run references |
| Fleet | Exercise simulated fleets of 10, 50, and 100 devices with delays and failures; measure duration, memory/CPU, storage growth, and concurrency limits |
| Device impact | Verify collection frequency, commands, and resource impact on representative real devices independently of simulated scale |
| TUI | Selected local workflows use the shared engine and remain usable as a standalone single binary |

Existing checks for code changes:

```sh
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
./tests/lab.sh test
```

Follow the [lab guide](../../tests/lab/README.md) for device tests. Fleet,
persistence, scheduler, and web acceptance tooling must be delivered with their
corresponding implementation. Existing synthetic tests do not establish those
future capabilities or real-device compatibility.

## Paid pilot and milestone decisions

For M3, record the buyer, repeated team workflow, agreed recurring benefit, scope,
annual price/currency, onboarding and support obligations, purchasing decision,
and private agreement/payment reference. Separate indicative interest, a quote,
and an actual paid commitment.

For every milestone decision, record:

```text
Milestone / review date / maintainer:
Evidence references and criteria assessed:
Decision: passed, failed, or evidence pending:
Remaining gaps and changes to scope or assumptions:
Next bounded task and owner:
```
