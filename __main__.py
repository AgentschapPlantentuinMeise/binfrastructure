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
# debug with /var/log/cloud-init* files
# cat /var/lib/cloud/instance/user-data.txt
user_data = """#!/bin/bash
#user_data script is executed as root
#echo 'Executed as' $(whoami) # $USER, whoami, id -nu or logname

if command -v yum &> /dev/null
then PACMAN=yum
elif command -v apt &> /dev/null
then PACMAN=apt
else
  echo No suitable package manager found
  exit 1
fi

sudo $PACMAN update -y
sudo $PACMAN upgrade -y
sudo $PACMAN install -y tmux #screen
sudo $PACMAN install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx
sudo $PACMAN install -y docker
sudo groupadd docker # group already exists
usermod -aG docker ec2-user
#newgrp docker
sudo systemctl enable docker
sudo systemctl start docker
sudo $PACMAN install -y git python3.11 python3.11-pip
#docker build -t b3app #https://github.com/AgentschapPlantentuinMeise/dockshop.git#binfrastructure
docker run -d -p 5000:5000 b3app
# nginx config and restart
## expand domain name as ec2 public name is too long for default config
sudo sed -i 's/http {/http { server_names_hash_bucket_size 128;/' /etc/nginx/nginx.conf

# Get PUBLIC_HOSTNAME
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
if command -v apt-get &> /dev/null
then
    sudo apt-get install cloud-utils
fi
if command -v ec2-metadata &> /dev/null
then
    PUBLIC_HOSTNAME=$(ec2-metadata --public-hostname | cut -f2 -d' ')
else
    PUBLIC_HOSTNAME=$(curl http://169.254.169.254/latest/meta-data/public-hostname)
fi

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
#sudo $PACMAN install -y nerdctl

# Install minikube (k8) -> needs 2CPU and 2GB RAM to operate
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-latest.x86_64.rpm
sudo rpm -Uvh minikube-latest.x86_64.rpm
cat <<EOF | sudo tee /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://pkgs.k8s.io/core:/stable:/v1.30/rpm/
enabled=1
gpgcheck=1
gpgkey=https://pkgs.k8s.io/core:/stable:/v1.30/rpm/repodata/repomd.xml.key
EOF
sudo $PACMAN install -y kubectl
su ec2-user -c 'minikube start' #--driver=podman --container-runtime=cri-o

# kompose
curl -L https://github.com/kubernetes/kompose/releases/download/v1.26.0/kompose-linux-amd64 -o kompose
chmod +x kompose
sudo mv ./kompose /usr/local/bin/kompose

# guardgraph installation
#sudo $PACMAN install python3-pip
#pip3 install --user podman-compose
su ec2-user -c 'mkdir ~/repos && cd ~/repos && git clone https://github.com/AgentschapPlantentuinMeise/guardgraph.git'

su - ec2-user <<"EOF"
  cd ~/repos/guardgraph
  
  ## build containers on minkube cluster
  # https://minikube.sigs.k8s.io/docs/handbook/pushing/#Linux
  #eval $(minikube docker-env)
  #docker build -t localhost/web .
  #minikube cache add localhost/web:latest
  #minikube addons enable registry
  #docker build --tag $(minikube ip):5000/web .
  #docker push $(minikube ip):5000/web
  minikube image build -t localhost/web .
  #minikube image build -t localhost/gis containers/gis
  
  ## convert compose setup #TODO move to readme for k8 documentatin
  #sed -i 's/3.9/3/' docker-compose.yml
  #sed -i 's/\${HOME}//g' docker-compose.yml
  #sed -i 's/repos/data/g' docker-compose.yml
  #kompose convert --volumes hostPath
  #
  #sed -i 's/image: localhost\/web:latest/imagePullPolicy: Never\\n\ \ \ \ \ \ \ \ \ \ image: localhost\/web:latest/' \
  #  web-deployment.yaml 
  
  kubectl apply -f $(ls -m k8config/*.yaml | tr -d ' \\n')
  #kubectl delete -f $(ls -m k8config/*.yaml | tr -d ' \\n')
  # List services
  kubectl get services
  # Describe service
  kubectl describe svc web
  
  # Connect nginx to k8 web container in minikube - https://minikube.sigs.k8s.io/docs/handbook/accessing/
  # https://faun.pub/accessing-a-remote-minikube-from-a-local-computer-fd6180dd66dd
  # allow port forwarding in range to include default flask port
  minikube start --extra-config=apiserver.service-node-port-range=1-65535
  # Add NodePort 5000 to web service
  kubectl patch svc web --type='json' -p '[{"op":"replace","path":"/spec/type","value":"NodePort"},{"op":"replace","path":"/spec/ports/0/nodePort","value":5000}]'
  # Forward internal minikube port to environment running minikube
  WEBSERVICEURL=$(minikube service web --url)
  # Need to allow network connections
  # https://www.uptimia.com/questions/fix-permission-denied-while-connecting-to-upstream-nginx-error
  sudo setsebool httpd_can_network_connect on
  sudo sed -i 's/localhost/'$(minikube ip)'/' /etc/nginx/conf.d/${PUBLIC_HOSTNAME}.conf
  sudo systemctl restart nginx
  
  # Activate web-site initialisation when all resources are ready
  if kubectl wait --for=condition=ready --timeout=4h -n default --all pods; then
      curl $WEBSERVICEURL/init
  else
      echo "K8 NOT READY YET! SOMETHIN PROBABLY WENT WRONG!"
  fi
EOF
"""
# Debug minikube
# kubectl get pods


#launch_template_resource = aws.ec2.LaunchTemplate(
#    "launchTemplateResource",
#    user_data=base64.b64encode(user_data.encode("ascii")).decode("ascii"),
#)
                                                  
b3server = aws.ec2.Instance(
    'b3-server',
    #instance_type="t2.micro", #t2 1CPU, t3 2CPU
    instance_type="t2.2xlarge", #t4g.2xlarge", # 8 vCPU 32 GB
    ami="ami-05f804247228852a3", #"ami-0111c5910da90c2a7","ami-0f61de2873e29e866",
    user_data=user_data,
    # user_data_base64=base64.b64encode(user_data.encode("ascii")).decode("ascii"),
    #launch_template=launch_template_resource,
    vpc_security_group_ids=[security_group.id],
    key_name=key_pair.key_name,
    root_block_device={"volume_size": 50}
)

pulumi.export('publicIp', b3server.public_ip)
pulumi.export('publicDns', b3server.public_dns)

# Machine learning instance
# Free tier of 3 months is finished
# role = aws.iam.Role('sagemaker-role',
#             assume_role_policy=json.dumps({
#                 'Version': '2012-10-17',
#                 'Statement': [{
#                     'Effect': 'Allow',
#                     'Principal': {'Service': 'sagemaker.amazonaws.com'},
#                     'Action': 'sts:AssumeRole',
#                 }],
#             }),
#             managed_policy_arns=['arn:aws:iam::aws:policy/AmazonSageMakerFullAccess']
#         )

# mli = aws.sagemaker.NotebookInstance("mli",
#     name="b3-notebook-instance",
#     role_arn=role.arn,
#     instance_type="ml.t2.medium",
#     tags={
#         "Name": "b3mli",
#     })
# pulumi.export('sagemakerDns', mli.url)

# Set up budget, sns & lambda to take down infrastructure if overspending
## ideally permanent low-cost infrastructure should be in separate stack that does not go down

# ec2shutdown_policy_doc = aws.iam.get_policy_document(
#     statements=[aws.iam.GetPolicyDocumentStatementArgs(
#         effect="Allow",
#         actions=["ec2:Describe*"],
#         resources=["*"],
# )])
# ec2shutdown_policy = aws.iam.Policy("ec2shutdown",
#     name="ec2shutdown",
#     description="Policy for shutting down ec2",
#     policy=ec2shutdown_policy_doc.json)
# current = aws.get_partition()
# assume_role = aws.iam.get_policy_document(statements=[aws.iam.GetPolicyDocumentStatementArgs(
#     effect="Allow",
#     principals=[aws.iam.GetPolicyDocumentStatementPrincipalArgs(
#         type="Service",
#         identifiers=[f"budgets.{current.dns_suffix}"],
#     )],
#     actions=["sts:AssumeRole"],
# )])
# ec2shutdown_role = aws.iam.Role("ec2shutdown",
#     name="ec2shutdown",
#     assume_role_policy=assume_role.json)
# b3_budget = aws.budgets.Budget("b3_budget",
#     name="b3_budget",
#     budget_type="USAGE",
#     limit_amount="150.0",
#     limit_unit="dollars",
#     #time_period_start="2006-01-02_15:04",
#     time_unit="MONTHLY")
# b3_budget_action = aws.budgets.BudgetAction("b3_budget",
#     budget_name=example_budget.name,
#     action_type="APPLY_IAM_POLICY",
#     approval_model="AUTOMATIC",
#     notification_type="ACTUAL",
#     execution_role_arn=example_role.arn,
#     action_threshold=aws.budgets.BudgetActionActionThresholdArgs(
#         action_threshold_type="ABSOLUTE_VALUE",
#         action_threshold_value=100,
#     ),
#     definition=aws.budgets.BudgetActionDefinitionArgs(
#         iam_action_definition=aws.budgets.BudgetActionDefinitionIamActionDefinitionArgs(
#             policy_arn=example_policy.arn,
#             roles=[example_role.name],
#         ),
#     ),
#     subscribers=[aws.budgets.BudgetActionSubscriberArgs(
#         address="example@example.example",
#         subscription_type="EMAIL",
#     )],
#     tags={
#         "Tag1": "Value1",
#         "Tag2": "Value2",
#     })

