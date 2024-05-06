"""An AWS Python Pulumi program"""

import pulumi
import pulumi_aws as aws
from pulumi_aws import s3

# Create an AWS resource (S3 Bucket)
bucket = s3.Bucket('b3-bucket',
    website=s3.BucketWebsiteArgs(
        index_document="index.html",
    ),
)
# Export the name of the bucket
pulumi.export('bucket_name', bucket.id)

# Create an S3 Bucket object
ownership_controls = s3.BucketOwnershipControls(
    'ownership-controls',
    bucket=bucket.id,
    rule=s3.BucketOwnershipControlsRuleArgs(
        object_ownership='ObjectWriter',
    ),
)

public_access_block = s3.BucketPublicAccessBlock(
    'public-access-block', bucket=bucket.id, block_public_acls=False
)

bucket_object = s3.BucketObject(
    'index.html',
    bucket=bucket.id,
    source=pulumi.FileAsset('index.html'),
    content_type='text/html',
    acl='public-read',
    opts=pulumi.ResourceOptions(depends_on=[public_access_block, ownership_controls]),
)

pulumi.export('bucket_endpoint', pulumi.Output.concat('http://', bucket.website_endpoint))

# EC2 resources
## Security group
security_group = security_group = aws.ec2.SecurityGroup(
    'b3server-secgrp',
    description='Enable HTTP access and ssh',
    ingress=[
        { # http
            'protocol': 'tcp',
            'from_port': 80,
            'to_port': 80,
            'cidr_blocks': ['0.0.0.0/0']
        },
        { # https
            'protocol': 'tcp',
            'from_port': 443,
            'to_port': 443,
            'cidr_blocks': ['0.0.0.0/0']
        },
        { # ssh
            'protocol': 'tcp',
            'from_port': 22,
            'to_port': 22,
            'cidr_blocks': ['0.0.0.0/0']
        },
    ],
    egress=[
        { # allow all outbound traffic
            'protocol': '-1',
            'from_port': 0,
            'to_port': 0,
            'cidr_blocks': ['0.0.0.0/0'],
            'ipv6_cidr_blocks': ['::/0']
        }
    ]
)

## EC2 instance
user_data = """
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
sudo yum install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx
sudo yum install -y docker
sudo systemctl enable docker
sudo systemctl start docker
sudo yum install -y git python3.11 python3.11-pip
"""

b3server = aws.ec2.Instance(
    'b3-server',
    instance_type="t2.micro",
    ami="ami-0f61de2873e29e866",
    user_data=user_data,
    vpc_security_group_ids=[security_group.id]
)

pulumi.export('publicIp', b3server.public_ip)

