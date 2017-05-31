# kubernetes-gelf-logger
Push logs from kubernetes instances to a gelf compatible server using udp.

This is to be used as described in the 'Cluster-level logging architectures' section of the kubernetes documentation on logging. (https://kubernetes.io/docs/concepts/cluster-administration/logging/)

PRs are welcome

# Environment variables used by the image:
- `GELF_ADDR` - Log server address (127.0.0.1:12201).

Prebuild image: `docker pull izissise/kubernetes-gelf-logger`
