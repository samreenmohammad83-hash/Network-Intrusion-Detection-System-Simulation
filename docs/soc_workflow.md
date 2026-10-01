# SOC Analyst Workflow

**Event -> Detection -> Alert -> Queue -> Triage -> Context -> Severity -> Escalate/Resolve -> Document**

Tier-1 style responsibilities demonstrated by the project:

- Validate whether the alert contains enough evidence.
- Review source, destination, protocol and port.
- Compare features against baseline.
- Check related alerts.
- Check whether activity is expected.
- Record investigation notes.
- Change status.
- Escalate when evidence requires deeper investigation.

This project intentionally does not automatically block traffic because it is an IDS simulation, not an IPS.
