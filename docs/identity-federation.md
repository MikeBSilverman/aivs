# Identity federation and passkeys

**Status:** member sign-in **built** (Phase M; §11 says what was built and
where it departs from the design below). Staff issuer, back-channel logout,
SCIM, passkeys and break-glass alerting: design agreed, unbuilt.
**Decision owner:** Mike Silverman.

How humans authenticate to the portal. Machine authentication is unaffected —
collectors present client certificates and never see any of this.

**Member users sign in over ordinary TLS.** AIVS is meant to be the platform an
ISAC and *all* its members work in, and a client certificate behind an overlay
network is within reach of a few dozen member firms with a PKI team, not of the
rest. So the member tenant described here was built first, and its users reach
the member portal on a separate public TLS listener: the ISAC's IdP and a
second factor, no client certificate, no local passwords, and sessions capped at
`TLP:AMBER+STRICT` with embargoed content kept on the certificate-bound path.
Certificates stay for machine collectors, ISAC staff, and anything `TLP:RED`.
Everything below about the two tenants, the issuer deciding authority, JIT
provisioning and passkeys stands; what changes is that, **for member users
only**, the certificate binding is no longer a precondition.

Read `auth/sessions.py` first. On the certificate-bound listener — staff, and
member people who sign in with a password, TOTP and their firm's certificate —
the certificate binding it describes is a precondition for everything here, not
something federation replaces. The two kinds of session refuse each other
(§11).

---

## 1. Two identity providers, because access is the ISAC's to revoke

**Decision: the ISAC operates two separate IdP tenants — one for member users,
one for its own staff — and AIVS is a relying party to both.**

The alternative, and the one this design started out assuming, was federating
outward to each member firm's own Okta or Entra tenant. It is superficially
attractive: no accounts for the ISAC to manage, and a firm's own joiner-mover-
leaver process does the work.

It is wrong for this system, for a reason that comes from how ISACs actually
operate: **a firm that stops being a member must stop having access, and that
decision belongs to the ISAC.** If identity is delegated to the member's IdP,
the ISAC's ability to cut off a lapsed, suspended or expelled member depends on
that member disabling their own accounts — which is precisely the party with the
least incentive to do it promptly, and no obligation the ISAC can enforce on a
timescale that matters. This is how large ISACs run it, and the reasoning
generalises to any ISAC.

So the ISAC holds both tenants:

| Tenant | Population | Administered by |
| --- | --- | --- |
| **Member IdP** | Analysts and submitters at member firms | The ISAC's membership team |
| **Staff IdP** | The ISAC's own employees | The ISAC's internal IT |

Okta and Ping are the two products in scope because they are what ISACs already
run; nothing in this design is specific to either.

A member firm's own IdP may still be chained *behind* the member tenant as an
upstream federation — that is a configuration inside the ISAC's Okta and AIVS
neither sees it nor cares. What matters is that the ISAC keeps a switch of its
own in front of it. Organisation status in AIVS remains a further, independent
kill switch: suspending an organisation cuts its people off regardless of what
either IdP says.

---

## 2. The invariant: the issuer decides what authority is reachable

**A token from the member issuer can never yield administrative authority, and a
token from the staff issuer can never act as a member organisation — regardless
of what the operator row says.**

This is the whole point of running two tenants, and it has to be enforced as a
property of the *session*, not as a role lookup that happens to agree. The
failure it prevents: the member tenant is the larger, more exposed, more
frequently-provisioned population, and if authority came from the database
alone, one takeover there plus one mistaken role assignment would be admin. The
two tenants would then be an administrative convenience rather than a security
boundary.

Concretely:

- `portal_sessions` records the issuer the session authenticated against.
- `resolve_session` re-checks it on every request, alongside the certificate,
  operator status and organisation status it already re-checks.
- The staff issuer resolves only to operators of the hosting ISAC
  (`org_type == ADMIN`); the member issuer resolves only to operators of member
  organisations. A mismatch is refused and audited — never downgraded to a
  lesser role, because a silent downgrade hides a misconfiguration that someone
  needs to fix.

Written as a permit-only allow-list, per `CLAUDE.md` §5. "Deny the staff routes
to member-issuer sessions" would leave every route added later exposed by
default.

---

## 3. OIDC profile

Authorization Code with PKCE, and nothing else. Both Okta and Ping support this
fully; SAML 2.0 is deferred until a named member firm's IAM team requires it,
at which point it is additive. Choosing OIDC first also means the weakest part
of SAML — IdP-initiated flows, where an unsolicited assertion arrives with no
request to correlate it to — never exists here at all.

Mandatory, all of them:

- `response_type=code`, PKCE `S256`. No implicit, no hybrid.
- SP-initiated only. An authentication response that does not correlate to a
  request this instance started is discarded.
- `nonce` bound to the pending login, `state` bound as below.
- ID token signature verified against the issuer's published JWKS, with `iss`,
  `aud`, `exp` and `nonce` all checked. Use a vetted JOSE implementation; the
  rule from `docs/encryption-design.md` §4 applies here too.
- Discovery documents and JWKS are fetched over TLS with the system trust
  store and cached with a bounded lifetime.

**`state` is bound to the browser that started the login.** This is the
non-obvious one. The round trip to the IdP leaves this site and comes back, and
without binding an authorization code obtained in one browser could be
redeemed in another — login CSRF, or a code lifted from a log or a referrer
signing the thief in as the victim. The design first bound `state` to the
client certificate; the public listener has none, so as built (`auth/oidc.py`)
the binding is a signed, ten-minute, `HttpOnly` pending-login cookie scoped to
`/portal/sso`, and a callback whose `state` is not the one in that cookie is
refused. The PKCE verifier and the `nonce` are derived from `state` by HMAC
under the session secret, so a stolen code is useless without the browser's
cookie and nothing about a pending login is stored server-side. A staff issuer
on the certificate-bound listener may add the fingerprint to that binding.

**The second factor is asserted by the IdP and insisted on here.** The IdP
performs it; AIVS refuses an ID token whose `amr` (RFC 8176) does not say `mfa`
or name at least two distinct methods, including one with no `amr` at all. A
sign-on policy edited to password-only would otherwise put single-factor
sessions on AMBER content from any browser, with nothing here noticing. The
methods are recorded on the session for the evidence pack.

**JOSE library: PyJWT.** One dependency, pure Python, verifying with
`cryptography`, which the server already carries, and maintained for over a
decade. Authlib would also have done the relying-party flow, at several times
the code and a second HTTP-client integration; the flow is one module
(`auth/oidc.py`) over `httpx`, and that module is where the checks above live,
so they are better read here than configured there. Algorithms are pinned to RS256, PS256, ES256
and ES384; `none` and HMAC algorithms are never accepted.

The client secret lives in the process environment alongside the database
credentials, not in the database. It is not a per-row secret and putting it in a
table would enlarge the at-rest problem described in
`docs/encryption-design.md` for no benefit.

---

## 4. Identity is `iss` + `sub`, never email

An operator links to a federated identity by issuer and subject, unique
together. Email is a display attribute and nothing more.

The failure this avoids is specific and has bitten other systems: an address is
reassigned after a departure — a shared alias, or a new joiner given a leaver's
address — and matching on email silently hands the new person the old person's
account, history and role. Subjects are not reassigned.

Email is still used once: to *locate* the pre-provisioned operator on first
federated login, at which point the link is written and never re-derived.
And only an address in one of the organisation's recorded mail domains is
used at all (`services/mail_domains.py`, Q41): the IdP asserts the address,
but the ISAC decides which domains are the firm's. Without that, a member
tenant able to set its users' `email` claim could create or link another
firm's person, keep the real firm from registering that address, and, with
the email intake on, receive that person's mail as its own drafts (threat
model R30). A person already linked signs in by issuer and subject whatever
later happens to the domain.

---

## 5. Provisioning, and what deprovisioning actually does

**Just-in-time provisioning: on by default for the member issuer, never
available on the staff issuer.**

This is the feature, not a convenience on the side of it. An ISAC's membership
operation is already automated from the directory outward — at a large ISAC, adding a
user to the right AD group is the single action, and entitlements flow from it.
Every downstream system that requires its own separate account creation step
becomes the one that is perpetually out of date: people who left months ago
still have access, new analysts wait days for it, and the membership team
maintains a roster by hand that the directory already knows.

So AIVS must be a system that AD automation reaches, not one that needs a
ticket. An account existing in the ISAC's member tenant *is* the ISAC's grant —
creating the AIVS operator on first login confers nothing the ISAC did not
already decide, so requiring a second manual step would add no security and
guarantee drift.

This is a deliberate departure from the default-deny instinct that governs the
rest of this codebase, and the reason it is safe to make is that the grant
already happened upstream, in a tenant the ISAC controls. The fail-closed
behaviour lives in the bounds instead:

- The organisation comes from the AD group that drives the rest of the
  membership automation: the ID token's group claim
  (`oidc_member_group_claim`) is matched against
  `organizations.directory_object_id`, which membership staff set at
  enrolment (the Organisations screen, or `PUT /api/v1/orgs/{id}/directory-group`;
  audited with the previous value). A group that maps to nothing, groups that map to two members, a
  group that maps to the hosting ISAC, or an organisation that is not `ACTIVE`
  refuses the login rather than creating anything — and each refusal is
  audited with its reason. This is what keeps a directory misconfiguration
  from inventing a member, or a member-tenant account from reaching staff
  authority. (The design named an organisation-slug claim; the group's object
  id is what the directory already has, and needs no claim mapping in the
  tenant.)
- The address must be in one of the organisation's mail domains, which
  membership staff record (§4). An organisation with none links and creates
  nobody new.
- The role is always `ANALYST`. Elevation is a deliberate act in AIVS, because
  the directory's groups describe membership, not editorial authority over other
  firms' embargoed content.
- Per-organisation opt-out, for a member that wants its roster managed
  explicitly. Off is the exception and should stay that way. *Not built:*
  `oidc_member_jit_provisioning` is instance-wide today.

**The same automation must be able to take access away, which JIT alone does not
do.** A directory-driven joiner process paired with a manual leaver process is
worse than neither, because the roster looks maintained. Group removal in AD
propagates to the tenant, which stops the next login — but the account already
in AIVS remains, and so does any live session. Back-channel logout (below)
covers the session; for the account, the natural fit given this is all
directory-driven is **SCIM provisioning from the tenant into AIVS**, so a
deactivation is pushed rather than inferred. Not v1, but the model to build
toward, and the reason the operator record keeps a federated link rather than
treating each login as standalone.

Staff accounts are created by hand. An administrator of the instance that holds
every member's embargoed intelligence should be an account somebody decided to
create.

**Deprovisioning is where federation earns its place, and where the honest limit
is.** Disabling the account in the IdP stops the next login; it does not by
itself end a live session. Three mechanisms together close that:

1. **Per-request re-validation.** `resolve_session` already re-checks operator
   and organisation status on every request — the same mechanism that makes
   certificate revocation take effect immediately. Deactivating an operator in
   AIVS is therefore already instant.
2. **OIDC back-channel logout.** Both Okta and Ping can call the instance when a
   user's session is terminated centrally; the endpoint revokes the matching
   portal sessions.
3. **A bounded maximum session age**, so that even with the back channel
   misconfigured, an IdP-side disable becomes effective within a known window
   rather than at the idle timeout's mercy.

State the residual plainly in the runbook: cutting off a departing analyst
instantly is a two-place action unless back-channel logout is configured —
disable in the IdP, and deactivate in AIVS. Suspending the whole organisation is
one place and immediate.

---

## 6. Passkeys

**A passkey replaces password + TOTP entirely for non-federated accounts.**

A discoverable WebAuthn credential with `userVerification: required` is
possession plus user verification, is bound to the origin, and cannot be
phished, relayed by a proxy, or read out of a database — the private key is in
the authenticator and AIVS stores only a public key. It is a stronger human
factor than the password and TOTP it replaces, so keeping the password
alongside it would retain the phishable factor the passkey exists to remove.
TOTP remains available for anyone who cannot use a passkey.

The organisation factor is unchanged: the session is still bound to the client
certificate. Passkey and certificate remain independent — the person and the
firm — which is the property `auth/sessions.py` is built around.

Details that matter:

- **The RP ID is the portal's hostname, and a passkey does not survive a change
  of origin.** This constrains any future split of the admin portal onto its own
  hostname: staff would have to re-enrol. If that split is ever wanted, decide it
  before passkeys are widely enrolled, not after.
- **Sign-count regression is treated as a cloned authenticator**: refuse and
  audit, rather than accept-and-log.
- **Attestation is not required** by default — requiring it means telling an
  analyst their authenticator brand is unacceptable, which is friction for
  little gain. Allow an ISAC to require it for staff accounts, since those are
  few and issued.
- **Recovery is administrator-initiated.** A self-service email reset would make
  the mailbox the real credential and undo the whole exercise. Losing every
  passkey means asking the ISAC to re-enrol you, which for this population is
  the correct amount of ceremony.

---

## 7. Break-glass, and why passkeys still matter when everyone is federated

If staff authentication depends entirely on the ISAC's Okta, an Okta outage
locks the ISAC out of its own instance — plausibly during the incident that
makes the instance matter most, since a widespread identity-provider outage and
a widespread security event are not independent events.

So: a small number of **local staff accounts, authenticated by passkey, that do
not depend on any IdP.** They are the reason the local authentication path is
kept rather than removed once federation ships. Their use is rare, so it is
alertable: any local-credential login by a staff account raises a notification
and an audit record, because outside an outage it is a signal worth looking at.

---

## 8. What this does not change

- **Machine access.** Collectors authenticate with certificates. Federation
  applies to the portal only.
- **The certificate requirement for staff and for RED.** Staff, and anyone
  reading `TLP:RED` or embargoed content, still sign in over the
  certificate-bearing path. For member users the requirement was deliberately
  lifted (the decision at the top of this document); what replaced it is a
  listener that serves the member portal and nothing else, and a ceiling on
  what its sessions can read (§11).
- **Authorization.** Roles, circles and the policy predicates are unchanged. The
  IdP says who someone is; AIVS continues to decide what they may do.

---

## 9. Configuration

All under the existing `AIVS_` prefix, with `extra="forbid"` still meaning a
typo refuses to start:

| Setting | Notes |
| --- | --- |
| `oidc_member_issuer`, `oidc_member_client_id`, `oidc_member_client_secret` | **Built.** Empty issuer disables member sign-in; the SSO routes then answer 404 |
| `oidc_member_redirect_uri` | **Built.** The public listener's `https://…/portal/sso/callback`, registered with the IdP. Explicit, because the public listener is a different origin from `public_base_url` |
| `oidc_member_group_claim` | **Built.** Claim listing directory groups; default `groups`. Matched against `organizations.directory_object_id` (§5) |
| `oidc_member_jit_provisioning` | **Built. Default on.** Creates `ANALYST` operators in `ACTIVE` organisations only; §5 argues why on is right here. Off, a person the member registered is still linked on first sign-in; nobody new is created |
| `sso_session_max_age_minutes` | **Built.** Upper bound on an SSO session's life, whatever the idle timeout allows; default 480, range 15–1440 |
| `sso_device_cookie_name` | **Built.** The per-browser cookie an SSO session is bound to; default `aivs_device` |
| `oidc_staff_issuer`, `oidc_staff_client_id`, `oidc_staff_client_secret` | Unbuilt. Empty issuer disables staff federation |
| `webauthn_rp_id`, `webauthn_rp_name` | Unbuilt. RP ID must match the portal hostname |

`validate_production_posture` refuses to start, in the permit-only shape, when
a member issuer is set and is not `https`, lacks a client id or secret, or has
no `https` redirect URI — rather than falling back to anything.

---

## 10. Build order

1. Schema and migration: federated-identity columns on `operators`, issuer on
   `portal_sessions`, a `webauthn_credentials` table. *Built for the member
   issuer (migration `7c4e2a91d5b3`); `webauthn_credentials` waits for step 5.*
2. The issuer↔authority invariant in `resolve_session`, with the authorization
   matrix extended to assert it — the matrix currently splits by surface, and
   gains a second axis. *Built for the member issuer, as `resolve_sso_session`
   and the matrix principal `member SSO session`.*
3. The OIDC relying-party flow, member issuer first. *Built (Phase M).*
4. Staff issuer, back-channel logout, session age bound. *The age bound is
   built, for SSO sessions; the rest is not.*
5. Passkeys: enrolment, authentication, administrator-initiated recovery.
6. Break-glass alerting.

Steps 1 and 2 land together. An issuer column that nothing enforces would be
exactly the failure `CLAUDE.md` §5 warns about — a security control that appears
in a row and is consulted by nothing.

---

## 11. Member sign-in as built (Phase M)

What exists, in the order a sign-in meets it. Requirement SF-65 pins it;
`threat-model.md` §B6 says what each part is for and what it leaves.

**The public listener.** nginx's third server block (8444, published only by
`docker-compose.public.yml`) asks for no client certificate and proxies an
allow-list of paths: the two SSO endpoints, and the member portal's dashboard,
own submissions and their member verbs (`submit`, `withdraw`), filing, search, the
vulnerability page and the two responses made from it (a one-click and the
firm's posture), signing out and static files. Everything else — the API, TAXII, the admin screens, the
staff review queue, the password sign-in form, the probes — is a 404 written
by nginx and never proxied. Sign-in is limited to ten a minute per address
(burst five) and pages to ten a second (burst twenty); per-subject lockout is
the IdP's, because no password is typed here. `deployment-topology.md` §2
places it among the network layers.

**Sign-in.** `GET /portal/sso/login` sends the browser to the IdP (§3: code
flow, PKCE S256, state in a signed cookie, nonce). `GET /portal/sso/callback`
correlates `state`, redeems the code, verifies the ID token, requires a
second factor in `amr`, and resolves the person (`services/sso.py`, §4–5).
Every refusal is audited as `portal.sso.login.refused` with its reason; the
browser is told only that sign-in was refused. Success is
`portal.sso.login.success`, with `amr` and whether the operator was just
provisioned.

**The session.** A new token at every sign-in, whatever cookie the browser
arrived with. It is bound to the issuer and subject, and to a per-browser
device cookie (`HttpOnly`, `Secure`, `SameSite=Strict`, 400 days) by its
SHA-256: a session cookie copied to another browser is refused. A database
constraint makes a session either certificate-bound or SSO-bound, never both
and never neither. Each request re-checks that the issuer is still the
configured member issuer, the device, the maximum age, that the operator is
active and still linked to that subject, and that the organisation is active
and is not the hosting ISAC. Its roles are intersected with `ANALYST` and
`ORG_ADMIN`, whatever the operator row holds. The callback answers with a page
that refreshes to the portal, because a `SameSite=Strict` cookie set on a
redirect that continues the IdP's cross-site navigation is not sent on it.

**Two kinds of session, each refused by the other's resolver.** A request with
a client certificate resumes only a certificate-bound session; one without
resumes only an SSO session. An SSO session presented beside a member
certificate is refused (`session_unbound`), which matters because it would
otherwise resolve without the ceiling. It is not a bearer credential on the
API or TAXII either.

**The ceiling.** `policy.tlp_ceiling(ctx)` is `AMBER+STRICT` for an SSO
session and `RED` otherwise, written so that a new session kind is unlimited
only if someone says so there. Every content read routes through it:
`distribution_visibility_clause` (the portal dashboard, and the services that
read distributed content), `tlp_ceiling_clause` passed to the TAXII listings as
a required argument (no SSO session reaches TAXII today, and the listing does
not rely on that), and for a firm's own filings both the list and count
(`tlp_ceiling_clause`) and `can_view_submission` (through
`submission_within_ceiling`): an SSO session neither sees nor opens its own
firm's RED or embargoed submission, and the list says what it leaves out. An SSO session also never reads a
submission that has an embargo, released or not.

**Signing out** lands on a page linking to `/portal/sso/login`. It is not a
redirect to the IdP, which would sign the person straight back in, nor to
`/portal/login`, which the public listener does not serve.

**Where the build departs from the design above.** `state` is bound to a
browser cookie, not a certificate (§3). The organisation comes from a
directory group's object id, not a slug claim (§5). Discovery and JWKS are
fetched at each sign-in rather than cached: an IdP key rotation takes effect at
once, at the cost of two extra requests to the IdP per sign-in. Not built:
per-organisation JIT opt-out, SCIM, back-channel logout, the staff issuer,
passkeys, and an end-to-end sign-in against a containerised IdP (the flow is
exercised against an in-process fake IdP; the listener itself is exercised
end to end).
