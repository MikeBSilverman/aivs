# aivs-schemas

The shared contract between an AIVS server and everything that talks to it.

Contains:

- **`enums.py`** — the shared vocabulary (organisation types, TLP 2.0
  designations, submission states) plus the submission state machine, declared
  once so the server, the CLI, the portal, and the tests cannot disagree about
  what a legal transition is.
- **`tlp.py`** — the TLP 2.0 marking-definition constants with their
  specification-mandated STIX identifiers.
- **`extension/`** — the AIVS STIX 2.1 property-extension for pre-CVE
  AI-discovered vulnerability data: its extension-definition SDO, its JSON
  Schema, and typed builders that produce valid STIX so that no caller has to
  hand-assemble it.
- **`models.py`** — Pydantic models for the native API request and response
  bodies.

This package deliberately carries almost no dependencies. Member firms import it
into their own environments, so every dependency added here lands in a GSIB's
software bill of materials.

Licensed under Apache-2.0.
