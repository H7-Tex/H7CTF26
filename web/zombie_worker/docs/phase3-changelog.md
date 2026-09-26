# Phase 3 packaging notes

The published report remains the gate to Relay's ordinary export flow. The historical v1 package metadata determines whether the private exporter includes commissioning material. Relay does not receive or log the runtime flag; only exporter receives `${FLAG}`. With the player-owned lifecycle revision, no private Chromium service is part of deployment. Candidate image references use immutable `phase3-v0.2.4` tags; publish and Anvil-instance validation are pending.
