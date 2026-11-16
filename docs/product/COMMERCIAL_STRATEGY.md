# Commercial strategy and hypotheses

Status: historical web/team product proposal. Superseded on 2026-11-13 by the
[standalone desktop roadmap](../../ROADMAP.md). The offers, subscription model,
milestones, and hosting assumptions below are research history, not current
requirements. Desktop commercial packaging is undecided.
Packaging, prices, demand, and revenue have not been validated.

## Buyer and value

Start with internal network teams managing roughly 10–100 devices. The engineer
uses the assessments; the team lead or budget owner buys a repeatable review and
handoff workflow. Discovery must establish the actual buyer and purchasing process.

Test whether teams value reduced collection/report preparation time, trustworthy
findings with less noise, clearer changes between assessments, and shared review
that leads to action or useful verification. Measure these outcomes in the
[pilot playbook](PILOT_PLAYBOOK.md) before treating them as selling claims.

## Proposed offers

| Offer | Value to validate | Revenue role and boundary |
| --- | --- | --- |
| Community | Open SSH library and assessment engine; basic single-operator web assessments, scheduling, local history, comparisons, and exports | Useful adoption path and contribution surface |
| Team | Shared review, finding ownership/acknowledgements, notes, shared policies, scheduled delivery, selected integrations, and supported releases | Primary recurring subscription; prioritize the smallest workflow that a pilot buyer values |
| Onboarding | Installation, credential/trust setup, initial assessment configuration, and an agreed integration | Fixed-scope early revenue and customer learning |
| Managed hosting | Operated workspace, upgrades, backups, and collection from inside the customer environment | Later subscription once demand and revenue can fund reliable operation |

Accuracy, truthful collection status, authenticated access, host verification,
secure credentials, and redaction are baseline capabilities. Basic local expected
conditions belong in the assessment engine; shared policy administration is a
possible team capability. Provider coverage grows with validation evidence.

These offers describe product direction. Existing code retains its current
license; this roadmap introduces no new billing or license enforcement behavior.

## First commercial experiment

1. Use discovery to identify a buyer, a current recurring job, and the cost or
   consequence of doing it with the current process.
2. Validate repeated use through M2, then select a shared workflow supported by
   concrete team examples. Keep an initial paid pilot bounded in scope.
3. Propose an annual subscription per team deployment. Record the actual offered
   price, currency, included deployment/scope, support obligations, and response.
   Establish the price through buyer conversations and quotes.
4. Record objections, buying friction, alternatives, and whether the decision is
   interest, a quote, a commitment, or payment. Secure a paid pilot before building
   billing infrastructure.
5. Review delivery/support cost and recurring benefit before expanding the offer.
   Introduce device bands if customer purchasing preferences or operating costs
   provide a reason to do so.

Agree support scope and availability explicitly. An initial solo, part-time
operation needs support commitments it can fulfill. Keep onboarding and custom
work fixed in scope, and favor improvements reusable across customer deployments.

## Business viability

Track annual subscription revenue, renewal intent and actual renewals when due,
hosting/infrastructure cost, onboarding effort, ongoing support hours, and
maintenance effort. Record the cost assumptions used to value founder time.

```text
Annual contribution per team = annual subscription price
  - annual infrastructure cost
  - annual support cost
  - onboarding cost not covered by the onboarding fee
```

Compare total contribution with shared maintenance, operating costs, and the
maintainer's income objective. Revenue targets and price assumptions remain open
until grounded in actual buyer and delivery evidence.

## Expansion opportunities

Evaluate advanced protocol assurance, change validation, and policy checks when
multiple teams repeatedly need the same capability. A paid module is a packaging
hypothesis to test after the workflow is proven. Evaluate MSP offerings separately
because customer isolation and multi-customer operation add requirements.

Evaluate managed hosting only after customers request it and the business can
support backups, upgrades, security, and incident handling. Larger fleets need
benchmarks and support capacity before a corresponding commercial promise.

Adjacent packaging examples are [NetBox's community, hosted, and self-hosted
editions](https://github.com/netbox-community/netbox/blob/main/docs/index.md) and
[Unimus's annual device-based and unlimited licensing](https://unimus.net/pricing.html).
Use them as research references; Omnisor's own willingness to pay requires direct
validation. Recheck external offers before relying on them in pricing research.
