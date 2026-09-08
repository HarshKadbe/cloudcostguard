# Minimum Read-Only IAM Policy for CloudCostGuard

This policy provides the least privileges required for CloudCostGuard to scan AWS resources.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity",
                "ec2:DescribeInstances",
                "ec2:DescribeInstancesStatus",
                "ec2:DescribeVolumes",
                "ec2:DescribeAddresses",
                "ec2:DescribeTags",
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:ListBucket",
                "s3:ListBucketVersions"
            ],
            "Resource": "*"
        }
    ]
}
```

## Additional permissions per service

### EC2
- `ec2:DescribeInstances` - for instance state and metadata
- `ec2:DescribeVolumes` - for EBS volume analysis
- `ec2:DescribeAddresses` - for Elastic IP analysis

### EBS
- Same as EC2 above

### Elastic IP
- Same as EC2

### S3
- `s3:ListAllMyBuckets` - to list buckets
- `s3:GetBucketLocation` - to determine bucket region
- `s3:ListBucket` - to list bucket contents
- `s3:ListBucketVersions` - to check object deletion status

## Notes

- This is a read-only policy - it does NOT include permissions to stop, terminate, or delete any resources
- The `Resource: "*"` is used because these are primarily describe/list operations
- For multi-account setups, restrict Resource ARNs as needed
- If using IAM users/roles, attach this policy to a read-only role
