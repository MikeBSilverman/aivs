# syntax=docker/dockerfile:1.7
# =============================================================================
# AIVS sharing server.
#
# Build from the REPOSITORY ROOT, not from this directory -- the build needs
# uv.lock and the sibling workspace packages:
#
#     docker build -f packages/aivs-server/Dockerfile -t aivs-server:local .
#
# (docker-compose.yml already does this: context `.`, dockerfile this file.)
#
# Two stages. The build stage has uv, the workspace sources and the machinery
# to resolve and compile a virtual environment. The runtime stage has that
# virtual environment, the interpreter, and as close to nothing else as a
# Debian slim image permits. Nothing that can install software survives into
# the running container: no uv, no pip, no compiler, no package index
# credentials.
# =============================================================================

# -----------------------------------------------------------------------------
# Base images.
#
# PINNING: these are tags, which are mutable. For any deployment that a
# third-party risk review will look at, pin by digest instead, so that the
# image a reviewer approved is byte-for-byte the image that runs:
#
#     docker buildx imagetools inspect python:3.12-slim-bookworm --format '{{.Manifest.Digest}}'
#     docker buildx imagetools inspect ghcr.io/astral-sh/uv:0.11.16 --format '{{.Manifest.Digest}}'
#
# then build with the digest form, which needs no edit to this file:
#
#     docker build \
#       --build-arg PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:<digest> \
#       --build-arg UV_IMAGE=ghcr.io/astral-sh/uv:0.11.16@sha256:<digest> \
#       -f packages/aivs-server/Dockerfile -t aivs-server:<version> .
#
# Record the digests in the release notes alongside the uv.lock hash. Refresh
# them deliberately (a base-image bump is a change to review), not implicitly
# on every rebuild.
#
# Debian slim rather than Alpine: the wheels for cryptography, psycopg and
# argon2-cffi are built against glibc, so Alpine would mean compiling them from
# source at build time -- more build tooling, slower builds, and a set of
# binaries nobody else is running or fuzzing.
# -----------------------------------------------------------------------------
ARG PYTHON_IMAGE=python:3.12-slim-bookworm
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.16

FROM ${UV_IMAGE} AS uv


# =============================================================================
# Build stage
# =============================================================================
FROM ${PYTHON_IMAGE} AS build

COPY --from=uv /uv /usr/local/bin/uv

# UV_PYTHON_DOWNLOADS=never  -- never silently fetch a different interpreter.
#   The runtime stage has the base image's Python; a mismatch produces a
#   virtual environment whose symlinks dangle at runtime.
# UV_NO_CACHE=1  -- no wheel cache in the layer. It would be dead weight in an
#   intermediate image and a place where a stale artefact could survive a
#   lockfile change.
# UV_PROJECT_ENVIRONMENT  -- build the environment at its FINAL path.
#   Console-script shebangs and pyvenv.cfg record absolute paths, so creating
#   it at /build/.venv and copying it to /opt would leave `aivs-server`
#   pointing at a directory that does not exist in the runtime image.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/aivs/venv

# No build-essential. Every dependency in uv.lock resolves to a manylinux wheel
# today, so a compiler would be unused weight and one more thing to keep
# patched. If a future dependency ships only an sdist, `uv sync` will fail here
# with a clear "failed to build" message -- add the toolchain to THIS stage
# then (it never reaches the runtime image), rather than reaching for a
# prebuilt fork of the dependency.

WORKDIR /build

# ---------------------------------------------------------------------------
# Layer 1: third-party dependencies only.
#
# Copying just the manifests and the lockfile first means this layer -- the
# expensive one -- is rebuilt only when a dependency actually changes, not on
# every source edit. --no-install-workspace skips the first-party packages,
# which is what makes that split possible.
#
# --frozen is the supply-chain control: uv installs exactly what uv.lock
# pins and FAILS if the lockfile and the pyproject files disagree. Without it,
# uv would silently re-resolve and the image could contain versions nobody
# reviewed. The lockfile is committed precisely so this is auditable.
#
# --no-dev keeps pytest, ruff, mypy, bandit and their transitive dependencies
# out of the image entirely.
#
# aivs-client is a workspace member, so its manifest must be present for uv to
# resolve the workspace, but --package aivs-server means it is never installed.
# ---------------------------------------------------------------------------
COPY pyproject.toml uv.lock ./
COPY packages/aivs-schemas/pyproject.toml packages/aivs-schemas/README.md packages/aivs-schemas/
COPY packages/aivs-server/pyproject.toml  packages/aivs-server/README.md  packages/aivs-server/
COPY packages/aivs-client/pyproject.toml  packages/aivs-client/README.md  packages/aivs-client/

RUN uv sync --frozen --no-dev --no-install-workspace --package aivs-server

# ---------------------------------------------------------------------------
# Layer 2: the first-party packages.
#
# --no-editable installs real wheels into site-packages instead of .pth files
# pointing back at /build. The runtime image therefore needs no source tree,
# and an attacker who somehow gets a write into a source directory has not
# thereby changed what the running interpreter imports.
# ---------------------------------------------------------------------------
COPY packages/aivs-schemas/src packages/aivs-schemas/src
COPY packages/aivs-server/src  packages/aivs-server/src

RUN uv sync --frozen --no-dev --no-editable --package aivs-server

# Fail the BUILD, not the first container start, if the package did not install
# cleanly. `python -m aivs_server.config` cannot be used here -- it exits
# non-zero by design when no configuration is present -- so import directly.
#
# The second check resolves the `aivs-server` console script's entry point and
# imports its target. A console script is generated from the pyproject metadata
# whether or not the module it names exists, so `test -x` would pass on a shim
# that fails at container start with an ImportError. If this step fails with
# "No module named 'aivs_server.__main__'", the fix is in
# packages/aivs-server/pyproject.toml: `[project.scripts]` names
# `aivs_server.__main__:main`, so either add that module or repoint the script
# at wherever `main()` actually lives.
RUN /opt/aivs/venv/bin/python -c "import aivs_server, aivs_schemas" \
 && test -x /opt/aivs/venv/bin/aivs-server \
 && /opt/aivs/venv/bin/python -c "\
import importlib.metadata as md; \
eps = [e for e in md.distribution('aivs-server').entry_points if e.name == 'aivs-server']; \
assert eps, 'no aivs-server console script in the installed metadata'; \
eps[0].load(); \
print('entry point resolves:', eps[0].value)"


# =============================================================================
# Runtime stage
# =============================================================================
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="aivs-server" \
      org.opencontainers.image.description="AIVS pre-CVE AI vulnerability sharing server" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/aequora/aivs"

# A fixed, high, system uid/gid. Fixed because docker-compose.yml, the tmpfs
# mount options and any volume permissions have to name the same number; high
# because it cannot then collide with a host user in a uid-namespace-less
# deployment. --no-log-init avoids the sparse-lastlog blowup that large uids
# cause with the default useradd behaviour.
RUN groupadd --system --gid 10001 aivs \
 && useradd  --system --no-log-init --uid 10001 --gid 10001 \
             --home-dir /app --shell /usr/sbin/nologin aivs

# Remove the installer toolchain from the SYSTEM interpreter. The application's
# virtual environment never had pip (uv does not install one), but the base
# image's site-packages does, and `python -m pip install ...` is the first move
# after a remote-code-execution foothold. Deleting it costs nothing: the image
# is immutable and everything it needs is already present.
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip \
           /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
           /usr/local/lib/python3.12/site-packages/setuptools \
           /usr/local/lib/python3.12/site-packages/setuptools-*.dist-info \
           /usr/local/lib/python3.12/site-packages/pkg_resources \
           /usr/local/lib/python3.12/site-packages/wheel \
           /usr/local/lib/python3.12/site-packages/wheel-*.dist-info \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12 \
 && rm -rf /var/lib/apt/lists/* /root/.cache

# Owned by root, not by the runtime user: the application must not be able to
# rewrite its own code. Combined with `read_only: true` in docker-compose.yml
# this is belt and braces, and it is the belt that survives someone removing
# the braces.
COPY --from=build --chown=root:root /opt/aivs/venv /opt/aivs/venv

# Alembic migrations. Shipped in the image so that `docker compose run --rm app
# alembic upgrade head` uses exactly the revisions that match this build,
# rather than whatever is checked out on the host. alembic.ini's
# `script_location = %(here)s/alembic` resolves to /app/alembic here.
WORKDIR /app
COPY --chown=root:root packages/aivs-server/alembic.ini /app/alembic.ini
COPY --chown=root:root packages/aivs-server/alembic     /app/alembic

# PYTHONDONTWRITEBYTECODE  -- the root filesystem is read-only, so a .pyc write
#   would raise on every import. The bytecode was compiled into the venv at
#   build time anyway (UV_COMPILE_BYTECODE above).
# PYTHONUNBUFFERED  -- logs must reach the platform's log driver as they
#   happen, not when a buffer fills. During an incident the lost tail of stdout
#   is the part you needed.
# PYTHONFAULTHANDLER  -- dump a native traceback on a segfault in a C extension
#   (cryptography, psycopg) instead of the container simply vanishing.
# PYTHONSAFEPATH  -- do not put the script's directory or the cwd on sys.path.
#   Without it, a file dropped into /app shadows a real module on next start.
ENV PATH="/opt/aivs/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONSAFEPATH=1

USER 10001:10001

# Documentation only -- docker-compose.yml deliberately publishes NO host port
# for this service. The application is reachable solely from the proxy over the
# compose-internal network, which is the first of the three controls that make
# header-derived identity safe.
EXPOSE 8000

# `python -m aivs_server.config` constructs the Settings object, which means it
# exercises every validator including validate_production_posture, and exits
# non-zero with a redacted message if anything is wrong. Using it as the
# healthcheck means a container running with a dev bypass enabled in production,
# or a malformed CIDR, is reported unhealthy instead of quietly serving.
#
# start-period covers first start; the check itself neither opens a socket nor
# touches the database, so it stays honest about configuration and says nothing
# about the database -- which is what the db service's own healthcheck is for.
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD ["python", "-m", "aivs_server.healthcheck"]

# The console script declared by packages/aivs-server/pyproject.toml
# ([project.scripts] aivs-server = "aivs_server.__main__:main"). Exec form, so
# the process is PID 1 and receives SIGTERM directly for a clean shutdown --
# there is no shell in between to swallow it.
CMD ["aivs-server"]
