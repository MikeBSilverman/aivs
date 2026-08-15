# Open decisions

Design notes for choices that are **not yet made**. Each states the current
behaviour, the options with their real costs, and a recommendation. When one is
settled, the reasoning moves into the code and the entry is replaced by a line
in the record at the bottom — a decision note that outlives its decision reads
as though the question is still open.

---

*Nothing is currently open.* The entries that were here have all been decided;
the record below says where each one's reasoning now lives.

---

## Decided

| Decision | Where the reasoning now lives |
|---|---|
| **Circle admission is the hosting ISAC's alone.** `can_administer_circle` returns `is_system_admin(ctx)`. A circle carries other members' embargoed intelligence and membership is backed by an agreement the ISAC holds; a cleared participant does not read in the next one. `CircleRole.CIRCLE_ADMIN` is retained but confers only what `contributor` does. | `auth/policy.can_administer_circle`, `aivs_schemas.enums.CircleRole`, `docs/authz-model.md` |
| **Bound visibility by membership start.** Joining a circle grants participation, never the back catalogue. `joined_at` is its own column and is settable, so a membership restored after an administrative mistake keeps the history it legitimately had. | `auth/policy.visible_content_clause`, `CLAUDE.md` §5, migration `d3f18a7c5b02` |
| **Bulk membership.** `POST /circles/{id}/members` takes identifiers and/or slugs; unknown names fail the whole batch, already-members are skipped so re-applying a roster is idempotent. | `services/circles.py` |
| **Rule-based groups.** `Circle.auto_member_org_types` materialises into ordinary membership rows, marked `managed_by_rule` so reconciliation only ever touches what it owns. Reconciled on circle creation, activation and suspension. | `services/circles.py`, migration `e5a92c11f7d4` |
| **Webhooks: contentless, and wired up.** The payload names the submission and collection and says "poll to collect". Fires when content becomes *visible* — distribution without an embargo, and embargo release — never at distribution under embargo. Queued inside the transaction that made the content visible, drained by a separate dispatcher with bounded retries. | `notify/events.py`, `notify/dispatcher.py`, migration `f7b3d40e9a15` |
| **Admin UI.** Organisations and circles are administered from the portal, through the same policy predicates and service functions as the API. | `portal/admin_routes.py` |
| **SBOM.** Reproducible CycloneDX 1.6 from the locked runtime environment, plus a syft scan of the image for the OS layer. | `scripts/generate-sbom.sh`, `CLAUDE.md` §2 |
