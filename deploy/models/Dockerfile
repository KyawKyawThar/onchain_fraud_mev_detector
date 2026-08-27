# syntax=docker/dockerfile:1
#
# The **model bundle image** for the ML detector (§20.2).
#
# Why a separate image rather than baking the weights into the detection image:
# models and code move on different clocks. A retrain should not require a code
# build, and a code deploy should not silently change which weights are serving.
# Making the bundle its own immutable, tagged artifact means the deployed model
# version is a line in the manifest — reviewable in a diff, rolled back by
# changing a tag, and pinned by digest if you want it airtight.
#
# It is also why there is no hot-swap path (§20.5): a new bundle is a new image
# tag, which is a new pod, which walks the same Shadow → backtest → Live gate as
# any other detector change. A model that could be swapped under a running
# process would make historical evidence unattributable.
#
# busybox because the image's whole job is to hold files an initContainer copies
# out (Kubernetes cannot mount an OCI image as a volume in stable APIs yet), and
# that copy needs a shell. ~2 MB.
FROM busybox:1.37.0-uclibc

# Directory holding the bundle, relative to the build context. Its layout must
# be exactly what `anomaly.json` names — see this directory's README.
ARG BUNDLE=.

COPY ${BUNDLE}/ /models/

# Fail the *build*, not the pod, on the mistake that actually happens: a bundle
# whose config references a path that isn't in it. Every `artifact_path` and
# `baseline` in anomaly.json must resolve inside /models.
RUN set -eux; \
    test -f /models/anomaly.json || { echo "bundle has no anomaly.json" >&2; exit 1; }; \
    grep -oE '"(artifact_path|baseline)"[[:space:]]*:[[:space:]]*"[^"]+"' /models/anomaly.json \
      | sed -E 's/.*"([^"]+)"$/\1/' \
      | while read -r referenced; do \
          test -f "${referenced}" || { echo "anomaly.json references missing ${referenced}" >&2; exit 1; }; \
        done

# Non-root, matching the detection image's uid so the copied files are readable
# without a fsGroup dance.
USER 10001:10001
