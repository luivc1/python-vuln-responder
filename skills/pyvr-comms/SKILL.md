---
name: pyvr-comms
description: Bilingual (English/Spanish) messages for a Python package vulnerability (first advisory - Pillow < 13.0.0) - team/colleague briefing with the fix steps, client notice for apps you maintain, and done confirmation. Use for "tell the team about the Pillow flaw", "brief colleagues", "avísale al equipo", "escribe a los clientes".
---

# Communications

Follow **pyvr-navigator** rules. Facts from the advisory and scan reports. Never
include exploit details beyond what the advisory states.

| Situation | Template (`templates/`) |
|---|---|
| Colleagues / dev team (Pillow) | `team-briefing.md` |
| Colleagues / dev team (HTTP2Shell, Brotli) | `team-briefing-brotli.md` |
| Clients whose apps you maintain | `client-notice.md` |
| Fixed and verified | `fixed-confirmation.md` |

Fill every `{{placeholder}}` from real data or drop the sentence. Use the client's
language. Draft only; sending is the user's approval.
