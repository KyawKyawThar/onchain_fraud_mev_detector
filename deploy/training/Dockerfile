# syntax=docker/dockerfile:1
#
# The **offline training image** (§20.1/§20.2) — the other side of the ONNX
# boundary.
#
# The contract between training and serving is deliberately *only* the ONNX
# artifact plus its `feature_version` ("train in whatever stack fits, serve in
# Rust"). This image is what fills the Python half of that contract for the two
# models §20.2 asks for, and it is a container rather than a README full of
# `pip install` lines for the obvious reason: a model is an audit artifact, so
# the toolchain that produced it has to be reproducible too.
#
# Everything is pinned exactly. Two of the pins are load-bearing rather than
# tidy:
#
#   - `onnxruntime` matches the version `deploy/Dockerfile` ships to production.
#     That is what lets this image *verify its own export* against the runtime
#     that will actually serve it — a converter bug or an opset mismatch fails
#     here, in a batch job, instead of at a pod's first block.
#   - `scikit-learn` and `skl2onnx` move together. skl2onnx supports a specific
#     window of scikit-learn versions, and a silently-unconverted estimator is
#     the failure mode that costs the most to debug.
FROM python:3.12-slim

# `--no-compile` keeps the layer smaller; nothing here is latency-sensitive.
RUN pip install --no-cache-dir --no-compile \
      numpy==2.5.2 \
      scipy==1.18.1 \
      scikit-learn==1.9.0 \
      skl2onnx==1.20.0 \
      onnx==1.22.0 \
      onnxruntime==1.29.0 \
      pyarrow==25.0.1 \
 && useradd -r -u 10001 trainer

COPY train.py /usr/local/bin/train.py

USER trainer
WORKDIR /work
ENTRYPOINT ["python", "/usr/local/bin/train.py"]
