"""An AWS Python Pulumi program"""

import pulumi
import pulumi_aws as aws
from pulumi_aws import s3

# Extra imports
import os
import base64
import json

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
### ssh key to connect

#ssh-keygen -t rsa -b 2048 -f b3-aws-key-pair # execute in ~/.ssh folder
#chmod g-r b3-aws-key-pair
#To login: ssh -i "b3-aws-key-pair" ec2-user@IPADRESS_SEE_EXPORT
# Read in the public key from the generated key pair file.
with open(os.path.expanduser('~/.ssh/b3-aws-key-pair.pub'), 'r') as key_file:
    public_key = key_file.read()

# Create a new AWS key pair using the public key string read from the file.
key_pair = aws.ec2.KeyPair('b3-key-pair', public_key=public_key)

# Export the key pair name to be used when launching EC2 instances.
pulumi.export('key_pair_name', key_pair.key_name)

# Script to initiate ec2 instance
user_data = """#!/bin/bash
#user_data script is executed as root
#echo 'Executed as' $(whoami) # $USER, whoami, id -nu or logname
sudo yum update -y
sudo yum upgrade -y
sudo yum install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx
sudo yum install -y docker
#sudo groupadd docker # group already exists
usermod -aG docker ec2-user
newgrp docker
sudo systemctl enable docker
sudo systemctl start docker
sudo yum install -y git python3.11 python3.11-pip
docker build -t b3app https://github.com/AgentschapPlantentuinMeise/dockshop.git#binfrastructure
docker run -d -p 5000:5000 b3app
# nginx config and restart
## expand domain name as ec2 public name is too long for default config
sudo sed -i 's/http {/http { server_names_hash_bucket_size 128;/' /etc/nginx/nginx.conf
PUBLIC_HOSTNAME=$(ec2-metadata --public-hostname | cut -f2 -d' ')
sudo sh -c "cat - > /etc/nginx/conf.d/${PUBLIC_HOSTNAME}.conf" <<EOF
server {
    listen 80;
    server_name $PUBLIC_HOSTNAME;
    location / {
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_pass http://localhost:5000;
    }
}
EOF
sudo systemctl restart nginx

# docker compose alternative
sudo yum install -y nerdctl

# Install minikube (k8) -> needs 2CPU and 2GB RAM to operate
#curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-latest.x86_64.rpm
#sudo rpm -Uvh minikube-latest.x86_64.rpm
#cat <<EOF | sudo tee /etc/yum.repos.d/kubernetes.repo
#[kubernetes]
#name=Kubernetes
#baseurl=https://pkgs.k8s.io/core:/stable:/v1.30/rpm/
#enabled=1
#gpgcheck=1
#gpgkey=https://pkgs.k8s.io/core:/stable:/v1.30/rpm/repodata/repomd.xml.key
#EOF
#sudo yum install -y kubectl

# guardgraph installation
su ec2-user -c 'mkdir ~/repos && cd ~/repos && git clone https://github.com/AgentschapPlantentuinMeise/guardgraph.git'
"""

#launch_template_resource = aws.ec2.LaunchTemplate(
#    "launchTemplateResource",
#    user_data=base64.b64encode(user_data.encode("ascii")).decode("ascii"),
#)
                                                  
b3server = aws.ec2.Instance(
    'b3-server',
    #instance_type="t2.micro", #t2 1CPU, t3 2CPU
    instance_type="c6g.4xlarge", #16 vCPU 32 GB
    ami="ami-0111c5910da90c2a7",#"ami-0f61de2873e29e866",
    user_data=user_data,
    # user_data_base64=base64.b64encode(user_data.encode("ascii")).decode("ascii"),
    #launch_template=launch_template_resource,
    vpc_security_group_ids=[security_group.id],
    key_name=key_pair.key_name
)

pulumi.export('publicIp', b3server.public_ip)
pulumi.export('publicDns', b3server.public_dns)

# Machine learning instance
role = aws.iam.Role('sagemaker-role',
            assume_role_policy=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'Service': 'sagemaker.amazonaws.com'},
                    'Action': 'sts:AssumeRole',
                }],
            }),
            managed_policy_arns=['arn:aws:iam::aws:policy/AmazonSageMakerFullAccess']
        )

mli = aws.sagemaker.NotebookInstance("mli",
    name="b3-notebook-instance",
    role_arn=role.arn,
    instance_type="ml.t2.medium",
    tags={
        "Name": "b3mli",
    })
pulumi.export('sagemakerDns', mli.url)
