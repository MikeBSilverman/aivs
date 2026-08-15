# Open decisions

Design notes for choices that are **not yet made**. Each states the current
behaviour, the options with their real costs, and a recommendation. When one is
settled, the reasoning moves into the code and the entry is replaced by a line
in the record at the bottom — a decision note that outlives its decision reads
as though the question is still open.

---

## 1. Who may change a sharing circle's membership?

**Still open.** The *technical* half of this was closed: content visibility is
now bounded by `circle_memberships.joined_at`, so adding an organisation to a
circle grants participation from that moment rather than the circle's entire
back catalogue. That was a defect whoever performed the change, and it is fixed.

What remains is the governance question.

**Current behaviour.** `auth/policy.can_administer_circle` permits the hosting
ISAC (`is_system_admin`) **or** any member organisation holding
`CircleRole.CIRCLE_ADMIN` in that circle. Circle roles attach to the
organisation's certificate, not to a named human. So a member firm can admit
another firm to a circle it administers, and the ISAC learns of it from an audit
row.

### Option A — restrict to the hosting ISAC

| | |
|---|---|
| **For** | Membership of a sharing circle *is* the trust boundary. In an ISAC it is a governance act, usually backed by a membership agreement, sector eligibility, and an NDA — not an operational one. Delegating it delegates the ISAC's own admission control, which is the thing members are paying for. One party grants access, which makes "who could see this, and when?" answerable from one place. |
| **Against** | Every membership change becomes an ISAC ticket. A sector-led working group that wants to self-manage cannot. This is a smaller cost than it was: rule-based membership now handles the bulk of routine changes without anyone filing anything, and the admin UI makes the remainder a form rather than a support request. |

### Option B — keep delegation as it stands

| | |
|---|---|
| **For** | A delegated circle admin can now only grant *future* delivery, not the archive, so the blast radius is bounded in the way that matters. Sector-led circles stay self-service. |
| **Against** | A member firm can still admit another firm to a circle carrying other members' embargoed content, without the ISAC being involved. For a product whose proposition is the ISAC's control over who is in the room, that is a claim with an exception in it. |

### Option C — member proposes, ISAC approves

| | |
|---|---|
| **For** | Keeps governance with the ISAC and the operational load with the people who want the change. |
| **Against** | A workflow, a notification path and a queue to build and secure, for a problem A does not leave unsolved now that the routine cases are automated. |

### Recommendation

**A.** The argument for delegation was mostly operational load, and rule-based
membership plus the admin UI have absorbed most of it. What is left is the
governance question, and for an ISAC-in-a-box the ISAC's control over admission
is the trust story being sold. Delegation is worth re-introducing when a
deploying ISAC asks for it — with the `joined_at` bound already in place to
limit what a delegated admin can hand over.

This is a one-line change (`can_administer_circle` returns
`is_system_admin(ctx)`), plus updating the authorization matrix. It has not been
made because it is a product decision rather than a defect.

---

## Decided

| Decision | Where the reasoning now lives |
|---|---|
| **Bound visibility by membership start.** Joining a circle grants participation, never the back catalogue. `joined_at` is its own column and is settable, so a membership restored after an administrative mistake keeps the history it legitimately had. | `auth/policy.visible_content_clause`, `CLAUDE.md` §5, migration `d3f18a7c5b02` |
| **Bulk membership.** `POST /circles/{id}/members` takes identifiers and/or slugs; unknown names fail the whole batch, already-members are skipped so re-applying a roster is idempotent. | `services/circles.py` |
| **Rule-based groups.** `Circle.auto_member_org_types` materialises into ordinary membership rows, marked `managed_by_rule` so reconciliation only ever touches what it owns. Reconciled on circle creation, activation and suspension. | `services/circles.py`, migration `e5a92c11f7d4` |
| **Webhooks: contentless, and wired up.** The payload names the submission and collection and says "poll to collect". Fires when content becomes *visible* — distribution without an embargo, and embargo release — never at distribution under embargo. Queued inside the transaction that made the content visible, drained by a separate dispatcher with bounded retries. | `notify/events.py`, `notify/dispatcher.py`, migration `f7b3d40e9a15` |
| **Admin UI.** Organisations and circles are administered from the portal, through the same policy predicates and service functions as the API. | `portal/admin_routes.py` |
| **SBOM.** Reproducible CycloneDX 1.6 from the locked runtime environment, plus a syft scan of the image for the OS layer. | `scripts/generate-sbom.sh`, `CLAUDE.md` §2 |
