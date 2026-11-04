# OpenShell protocol

`proto/` is NVIDIA OpenShell's supervisor-middleware protocol (`supervisor_middleware.proto` and the
`extension.proto` it imports), verbatim from [NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) at v0.1.6
(`ac7f615cd12d5cc49cb16eb1f5f10ffeb1e90f47`), under the Apache License 2.0 (Copyright NVIDIA Corporation & Affiliates).
The guard's Go stubs in `pkg/guard/openshellpb` are generated from it by `scripts/openshell-proto.sh`, which pins the
commit, protoc and the Go plugins; to move to another OpenShell release, change `COMMIT` there and run it.
