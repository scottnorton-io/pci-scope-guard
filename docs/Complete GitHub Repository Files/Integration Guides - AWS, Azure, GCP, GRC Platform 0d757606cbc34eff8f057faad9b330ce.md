# Integration Guides - AWS, Azure, GCP, GRC Platforms

# Integration Guides

**Complete setup instructions for all cloud providers and GRC platforms**

---

## AWS Integration Guide

### Prerequisites

- AWS account with appropriate permissions
- AWS CLI installed and configured
- PCI Scope Guard deployed

### IAM Policy Setup

### Minimum Required Permissions (Read-Only)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PCIScopeGuardDiscovery",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeTags",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "rds:ListTagsForResource",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTags",
        "lambda:ListFunctions",
        "lambda:ListTags",
        "lambda:GetFunction",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketTagging",
        "s3:GetEncryptionConfiguration",
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "ecs:ListTagsForResource",
        "eks:ListClusters",
        "eks:DescribeCluster"
      ],
      "Resource": "*"
    },
    {
      "Sid": "PCIScopeGuardFlowLogs",
      "Effect": "Allow",
      "Action": [
        "logs:StartQuery",
        "logs:GetQueryResults",
        "logs:DescribeLogGroups"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/vpc/flowlogs*"
    },
    {
      "Sid": "PCIScopeGuardTagging",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateTags",
        "rds:AddTagsToResource",
        "elasticloadbalancing:AddTags",
        "lambda:TagResource",
        "s3:PutBucketTagging",
        "ecs:TagResource",
        "eks:TagResource"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": ["us-east-1", "us-west-2"]
        }
      }
    }
  ]
}
```

### Create IAM User

```bash
# Create IAM user
aws iam create-user --user-name pci-scope-guard

# Create policy
aws iam create-policy \
  --policy-name PCIScopeGuardPolicy \
  --policy-document [file://pci-scope-guard-policy.json](file://pci-scope-guard-policy.json)

# Attach policy to user
aws iam attach-user-policy \
  --user-name pci-scope-guard \
  --policy-arn arn:aws:iam::123456789012:policy/PCIScopeGuardPolicy

# Create access key
aws iam create-access-key --user-name pci-scope-guard
```

### Alternative: IAM Role (Recommended for ECS/EKS)

```bash
# Create assume role policy
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "[ecs-tasks.amazonaws.com](http://ecs-tasks.amazonaws.com)"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create role
aws iam create-role \
  --role-name PCIScopeGuardRole \
  --assume-role-policy-document [file://trust-policy.json](file://trust-policy.json)

# Attach policy
aws iam attach-role-policy \
  --role-name PCIScopeGuardRole \
  --policy-arn arn:aws:iam::123456789012:policy/PCIScopeGuardPolicy
```

### Enable VPC Flow Logs

```bash
# Create CloudWatch log group
aws logs create-log-group --log-group-name /aws/vpc/flowlogs

# Create IAM role for Flow Logs
aws iam create-role \
  --role-name VPCFlowLogsRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "[vpc-flow-logs.amazonaws.com](http://vpc-flow-logs.amazonaws.com)"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach policy
aws iam put-role-policy \
  --role-name VPCFlowLogsRole \
  --policy-name CloudWatchLogPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Resource": "*"
    }]
  }'

# Enable Flow Logs for VPC
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-12345678 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs \
  --deliver-logs-permission-arn arn:aws:iam::123456789012:role/VPCFlowLogsRole
```

### Configuration

Add to `.env`:

```bash
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_ENABLE_FLOW_LOGS=true
AWS_FLOW_LOG_GROUP=/aws/vpc/flowlogs
```

### Test Connection

```bash
pci-scope-guard integrations test aws
```

### Run First Scan

```bash
pci-scope-guard scan --cloud aws --region us-east-1
```

---

## Azure Integration Guide

### Prerequisites

- Azure subscription
- Azure CLI installed
- Contributor or Custom Role with required permissions

### Create Service Principal

```bash
# Login to Azure
az login

# Create service principal
az ad sp create-for-rbac \
  --name "pci-scope-guard" \
  --role Reader \
  --scopes /subscriptions/{subscription-id}

# Output will show:
# {
#   "appId": "...",      # AZURE_CLIENT_ID
#   "password": "...",   # AZURE_CLIENT_SECRET
#   "tenant": "..."      # AZURE_TENANT_ID
# }
```

### Custom Role (Optional, for Tagging)

```bash
# Create custom role definition
cat > pci-scope-guard-role.json <<EOF
{
  "Name": "PCI Scope Guard",
  "IsCustom": true,
  "Description": "Read access plus tagging for PCI scope management",
  "Actions": [
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/virtualMachines/write",
    "[Microsoft.Network/networkInterfaces/read](http://Microsoft.Network/networkInterfaces/read)",
    "[Microsoft.Network/networkSecurityGroups/read](http://Microsoft.Network/networkSecurityGroups/read)",
    "[Microsoft.Network/virtualNetworks/read](http://Microsoft.Network/virtualNetworks/read)",
    "Microsoft.Sql/servers/databases/read",
    "Microsoft.Sql/servers/read",
    "Microsoft.Web/sites/read",
    "[Microsoft.Storage/storageAccounts/read](http://Microsoft.Storage/storageAccounts/read)",
    "Microsoft.Resources/tags/write"
  ],
  "NotActions": [],
  "AssignableScopes": [
    "/subscriptions/{subscription-id}"
  ]
}
EOF

# Create role
az role definition create --role-definition pci-scope-guard-role.json

# Assign to service principal
az role assignment create \
  --assignee {appId} \
  --role "PCI Scope Guard" \
  --scope /subscriptions/{subscription-id}
```

### Enable NSG Flow Logs

```bash
# Create storage account for flow logs
az storage account create \
  --name pciscopeguardlogs \
  --resource-group pci-scope-guard \
  --location eastus \
  --sku Standard_LRS

# Enable NSG flow logs
az network watcher flow-log create \
  --resource-group pci-scope-guard \
  --nsg {nsg-name} \
  --name {flow-log-name} \
  --storage-account pciscopeguardlogs \
  --enabled true \
  --retention 7
```

### Configuration

Add to `.env`:

```bash
AZURE_SUBSCRIPTION_ID=...
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
```

### Test Connection

```bash
pci-scope-guard integrations test azure
```

---

## GCP Integration Guide

### Prerequisites

- GCP project
- gcloud CLI installed
- Project Editor or Custom Role

### Create Service Account

```bash
# Create service account
gcloud iam service-accounts create pci-scope-guard \
  --display-name="PCI Scope Guard" \
  --description="Service account for PCI scope discovery"

# Grant required roles
gcloud projects add-iam-policy-binding {project-id} \
  --member="serviceAccount:pci-scope-guard@{project-id}.[iam.gserviceaccount.com](http://iam.gserviceaccount.com)" \
  --role="roles/compute.viewer"

gcloud projects add-iam-policy-binding {project-id} \
  --member="serviceAccount:pci-scope-guard@{project-id}.[iam.gserviceaccount.com](http://iam.gserviceaccount.com)" \
  --role="roles/cloudsql.viewer"

gcloud projects add-iam-policy-binding {project-id} \
  --member="serviceAccount:pci-scope-guard@{project-id}.[iam.gserviceaccount.com](http://iam.gserviceaccount.com)" \
  --role="roles/container.viewer"

gcloud projects add-iam-policy-binding {project-id} \
  --member="serviceAccount:pci-scope-guard@{project-id}.[iam.gserviceaccount.com](http://iam.gserviceaccount.com)" \
  --role="roles/logging.viewer"

# Create and download key
gcloud iam service-accounts keys create ~/pci-scope-guard-key.json \
  --iam-account=pci-scope-guard@{project-id}.[iam.gserviceaccount.com](http://iam.gserviceaccount.com)
```

### Enable VPC Flow Logs

```bash
# Enable for subnet
gcloud compute networks subnets update {subnet-name} \
  --region={region} \
  --enable-flow-logs \
  --logging-aggregation-interval=interval-5-sec \
  --logging-flow-sampling=1.0
```

### Configuration

Add to `.env`:

```bash
GCP_PROJECT_ID={project-id}
GCP_CREDENTIALS_PATH=/app/keys/gcp-credentials.json
```

### Test Connection

```bash
pci-scope-guard integrations test gcp
```

---

## Vanta Integration Guide

### Prerequisites

- Vanta account
- API token with write access

### Generate API Token

1. Log in to Vanta
2. Go to Settings → API Tokens
3. Click "Generate New Token"
4. Name: "PCI Scope Guard"
5. Permissions: `resource:write`, `custom_attribute:write`
6. Copy token (shown only once)

### Configuration

Add to `.env`:

```bash
VANTA_API_KEY=vanta_api_...
VANTA_API_URL=[https://api.vanta.com](https://api.vanta.com)
```

### Custom Attributes Setup

PCI Scope Guard creates these custom attributes in Vanta:

- `pci_scope` - Scope classification (cde, connected-cde, out-of-scope)
- `pci_data_classification` - Data handling type
- `pci_segment` - Network segment
- `pci_validated_date` - Last validation timestamp
- `pci_validated_by` - Who validated the scope

### Sync Resources

```bash
# One-time sync
pci-scope-guard integrations sync vanta

# Scheduled sync (cron)
0 */6 * * * /usr/local/bin/pci-scope-guard integrations sync vanta
```

### Verification

In Vanta:

1. Go to Inventory
2. Select a resource
3. Check Custom Attributes tab
4. Verify `pci_scope` field is populated

---

## Drata Integration Guide

### Prerequisites

- Drata account
- API key with appropriate permissions

### Generate API Key

1. Log in to Drata
2. Go to Settings → Integrations → API Keys
3. Click "Create API Key"
4. Name: "PCI Scope Guard"
5. Scopes: `assets:write`, `evidence:write`
6. Copy key

### Configuration

Add to `.env`:

```bash
DRATA_API_KEY=drata_...
DRATA_API_URL=[https://api.drata.com](https://api.drata.com)
```

### Webhook Configuration (Optional)

For real-time updates:

1. In Drata, go to Settings → Webhooks
2. Create new webhook
3. URL: [`https://your-pci-scope-guard.com/api/v1/webhooks/drata`](https://your-pci-scope-guard.com/api/v1/webhooks/drata)
4. Events: `asset.created`, `asset.updated`, `asset.deleted`
5. Copy signing secret to `.env`:

```bash
DRATA_WEBHOOK_SECRET=whsec_...
```

### Sync Resources

```bash
pci-scope-guard integrations sync drata
```

---

## SecureFrame Integration Guide

### Prerequisites

- SecureFrame account
- API token

### Generate API Token

1. Log in to SecureFrame
2. Go to Settings → API
3. Generate new token
4. Permissions: Read/Write for Assets
5. Copy token

### Configuration

Add to `.env`:

```bash
SECUREFRAME_API_KEY=sf_...
SECUREFRAME_API_URL=[https://api.secureframe.com](https://api.secureframe.com)
```

### Sync Resources

```bash
pci-scope-guard integrations sync secureframe
```

---

## Troubleshooting

### AWS "Access Denied" Errors

```bash
# Test IAM permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/pci-scope-guard \
  --action-names ec2:DescribeInstances rds:DescribeDBInstances

# Check if policy is attached
aws iam list-attached-user-policies --user-name pci-scope-guard
```

### Azure "Authorization Failed"

```bash
# Verify service principal
az ad sp list --filter "displayName eq 'pci-scope-guard'"

# Check role assignments
az role assignment list --assignee {appId}
```

### GCP "Permission Denied"

```bash
# Test service account
gcloud auth activate-service-account \
  --key-file=pci-scope-guard-key.json

# List granted roles
gcloud projects get-iam-policy {project-id} \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:pci-scope-guard*"
```

### GRC Platform "Invalid API Key"

```bash
# Test API connection
curl -H "Authorization: Bearer $VANTA_API_KEY" [https://api.vanta.com/v1/resources](https://api.vanta.com/v1/resources)

# Check token expiration
pci-scope-guard integrations status vanta
```

---

**Document Version**: 1.0

**Last Updated**: December 2025

**Author**: Scott Norton