# External publisher-signed runtime registry

## Intent

Allow an operator to provision a publisher-signed function catalog and a
separately trusted publisher public key to the executor. The executor must
verify the catalog and bind every signed record to the exact embedded WASM
module it can dispatch before starting either PIR server. This moves the
signing authority outside the worker process and lets the signature identify a
publisher whose public key was pinned by deployment configuration.

## Approaches

1. **Provision a manifest and pinned key as files.** The worker reads a bounded
   signed catalog and a 32-byte Ed25519 public key from configured paths. This
   fits the existing worker startup and PIR record flow, does not expose the
   signing key to the executor, and requires a restart to install a new
   catalog. This is the selected approach.
2. **Extend the private bootstrap protocol to carry a catalog.** This avoids
   shared files but changes client provisioning, worker framing, and startup
   failure handling without adding a publisher trust source.
3. **Fetch a catalog from a registry service.** This supports remote updates but
   needs authenticated transport, availability policy, and monotonic version
   handling that the local prototype does not yet provide.

## Configuration and checks

Set both `OBLIVION_REGISTRY_MANIFEST` and
`OBLIVION_REGISTRY_PUBLIC_KEY`, or set neither. The manifest file contains the
versioned binary encoding produced by `oblivion-registry`; the public key file
contains exactly 32 raw Ed25519 public-key bytes. Partial configuration,
oversized/non-regular inputs, malformed manifests, invalid signatures, and
catalogs that do not exactly match the five dispatchable embedded WASM modules
fail startup before the worker announces readiness.

Create a private seed outside the runtime, restrict it to its owner, and use
the offline example to create a new output directory containing both files:

```sh
umask 077
openssl rand 32 > publisher.seed
cargo run -p oblivion-server --example publish-registry -- \
  publisher.seed 1 ./published-catalog-v1
```

For a local demo, point the worker's inherited environment at those files:

```sh
OBLIVION_REGISTRY_MANIFEST=./published-catalog-v1/registry.bin \
OBLIVION_REGISTRY_PUBLIC_KEY=./published-catalog-v1/publisher.pub \
cargo run -p oblivion-server -- demo ./demo-output 50 1 mixed
```

The output directory must not already exist. Back up and protect the private
seed independently; the public key and catalog may be distributed together
only after the public key has been authenticated through the deployment trust
channel.

The public key is a trust root and must be delivered through an independent
trusted deployment channel. A signature proves that the holder of the
corresponding private key signed this catalog; it does not prove that the key
belongs to a named organization unless the operator has authenticated that
binding. The runtime never reads or creates a publisher private key in external
catalog mode.

When neither variable is set, the development demo retains its existing
ephemeral local signer. That compatibility mode does not authenticate an
external publisher and is not equivalent to external-catalog mode.

## Limits

The worker pins records for its process lifetime and verifies each selected
PIR record against those exact bytes. Catalog versions are signed, but this
change does not add an independently durable monotonic catalog-version anchor,
remote publication, partial-catalog inclusion proofs, or live catalog
rotation. The record location digest remains synthetic for the embedded-module
demo. An executor that is trusted can inspect the catalog, selected function,
and module bytes.
