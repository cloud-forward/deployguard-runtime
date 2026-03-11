# deployguard-runtime Helm Chart

DeployGuard Runtime Agent — runs as a **DaemonSet** on every node in your cluster to provide runtime security monitoring.

## Requirements

- Kubernetes 1.21+
- Helm 3.x
- EKS / self-managed K8s

## Quick Install

```bash
# Add the repo (once published)
helm repo add deployguard https://charts.deployguard.io
helm repo update

# Install into its own namespace
helm install deployguard-runtime deployguard/deployguard-runtime \
  --namespace deployguard \
  --create-namespace
```

Or from local chart:

```bash
helm install deployguard-runtime ./deployguard-runtime \
  --namespace deployguard \
  --create-namespace
```

## Install with API Key

```bash
helm install deployguard-runtime deployguard/deployguard-runtime \
  --namespace deployguard \
  --create-namespace \
  --set secret.enabled=true \
  --set secret.data.DEPLOYGUARD_API_KEY="your-api-key-here"
```

## EKS with IRSA (IAM Role for Service Account)

```bash
helm install deployguard-runtime deployguard/deployguard-runtime \
  --namespace deployguard \
  --create-namespace \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"="arn:aws:iam::123456789:role/deployguard-role"
```

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Container image | `deployguard-runtime` |
| `image.tag` | Image tag | `latest` |
| `image.pullPolicy` | Pull policy | `IfNotPresent` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `hostPID` | Share host PID namespace | `false` |
| `hostNetwork` | Share host network | `false` |
| `secret.enabled` | Enable Secret resource | `false` |
| `secret.data` | Key-value pairs for Secret | `{}` |
| `serviceAccount.annotations` | Annotations (e.g. IRSA) | `{}` |
| `config.data` | Agent config file contents | see values.yaml |

## Upgrade

```bash
helm upgrade deployguard-runtime deployguard/deployguard-runtime \
  --namespace deployguard \
  --reuse-values \
  --set image.tag="1.2.0"
```

## Uninstall

```bash
helm uninstall deployguard-runtime --namespace deployguard
```
