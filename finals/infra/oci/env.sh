#!/usr/bin/env bash
# h7ctf'26 finals - oci infra environment (sourced by all scripts)
# run from the ops VM (instance principal) or sage for read-only queries.
# never edit after provisioning starts; use the locked OCIDs in inventory.json.

set -euo pipefail

TENANCY=ocid1.tenancy.oc1..aaaaaaaaafxbo7koftkhup62ysf6kdebvx7k4cqqmu6dgo6rktadkeh7ilgq
export AD=ljcT:AP-HYDERABAD-1-AD-1
export REGION=ap-hyderabad-1

# compartment - set after bootstrap (00-bootstrap.md)
export C=${H7F_COMPARTMENT_ID:-}

# number of real teams (NOP = N+1 = 16)
export N=15

# latest canonical ubuntu 24.04 image for the region (re-query with 50-images.sh list-base)
export IMG_UBUNTU=${H7F_IMG_UBUNTU:-ocid1.image.oc1.ap-hyderabad-1.aaaaaaaa3k7lllnzsvjppjzklqx3ixjjv5jgsxmhq3ykifxjqz2t3xbmtlq}

# golden images - set after 50-images.sh completes
export IMG_PROD=${H7F_IMG_PROD:-}
export IMG_WB=${H7F_IMG_WB:-}

# networking ids - set after 10-network.sh
export VCN_ID=${H7F_VCN_ID:-}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR
export INVENTORY="$SCRIPT_DIR/inventory.json"

# init inventory if absent
[[ -f "$INVENTORY" ]] || echo '{}' > "$INVENTORY"
