# binfrastructure
B-cubed infrastructure as code repository

# Secret configuration

    pulumi config set --secret binfrastructure:gbifPassword


# Mail server

Do get the postfix server working, configuration on the server is
vital, as well as setting up the routing instructions on the DNS.

## Server configuration

     sudo dnf -y install postfix
     sudo systemctl start postfix
     sudo systemctl enable postfix
     sudo postmap /etc/postfix/virtual
     echo mail.guardin.net > /etc/hostname
     echo 51.44.14.23 mail.guardin.net >> /etc/hosts
     # Create user/mailbox
     sudo useradd -m -s /bin/bash mbg # example to receive mail on mbg@guardin.net

Check mails with `sudo cat /var/spool/mail/mbg | tail -n16`

Postfix configuration retrieved with `postconf -pn`

    alias_database = hash:/etc/aliases
    alias_maps = hash:/etc/aliases
    command_directory = /usr/sbin
    compatibility_level = 2
    daemon_directory = /usr/libexec/postfix
    data_directory = /var/lib/postfix
    debug_peer_level = 2
    debugger_command = PATH=/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin ddd $daemon_directory/$process_name $process_id & sleep 5
    html_directory = no
    inet_interfaces = all
    inet_protocols = ipv4
    mail_owner = postfix
    mailq_path = /usr/bin/mailq.postfix
    manpage_directory = /usr/share/man
    meta_directory = /etc/postfix
    mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain
    mydomain = guardin.net
    myhostname = mail.guardin.net
    newaliases_path = /usr/bin/newaliases.postfix
    queue_directory = /var/spool/postfix
    readme_directory = /usr/share/doc/postfix/README_FILES
    sample_directory = /usr/share/doc/postfix/samples
    sendmail_path = /usr/sbin/sendmail.postfix
    setgid_group = postdrop
    shlib_directory = /usr/lib64/postfix
    smtp_tls_CAfile = /etc/pki/tls/certs/ca-bundle.crt
    smtp_tls_CApath = /etc/pki/tls/certs
    smtp_tls_security_level = may
    smtpd_tls_cert_file = /etc/pki/tls/certs/postfix.pem
    smtpd_tls_key_file = /etc/pki/tls/private/postfix.key
    smtpd_tls_security_level = may
    unknown_local_recipient_reject_code = 550

## DNS configuration

|Record name|Type|Routing policy|Differentiator|Alias|Value/Route traffic to|TTL (seconds)|Health check ID|Evaluate target health|Record ID|
|guardin.net|MX|Simple|-|No|10 mail.guardin.net|300|-|-|-|
|mail.guardin.net|A|Simple|-|No|51.44.14.23|300|-|-|-|

## Security configuration

Add type SMTP port 25 to inbound rules security group

# Backup minikube and server

Backup minikube data on server

    rsync -avz -e "ssh -i $(minikube ssh-key)" docker@$(minikube ip):/data/worker ~/backup
    rsync -avz -e 'ssh -i ".ssh/b3-aws-key-pair"' ec2-user@www.guardin.net:/home/ec2-user/backup/worker data/guardin
    
Or in one command

    ssh -i ".ssh/b3-aws-key-pair" ec2-user@www.guardin.net \
    'rsync -avz -e "ssh -i $(minikube ssh-key)" \
    docker@$(minikube ip):/data/worker ~/backup' && \
    rsync -avz -e 'ssh -i ".ssh/b3-aws-key-pair"' \
    ec2-user@www.guardin.net:/home/ec2-user/backup/worker data/guardin

# Debug minikube
## Get logs init container

    kubectl logs neo4j-8b6959445-6bkzk -c get-globi

## Set gbif pwd in live container

    minikube ssh
    CONTAINERID=$(docker container ls | grep worker | head -n1 | cut -f1 -d' ')
    docker exec -it $CONTAINERID /bin/bash
    echo $GBIF_PWD > gbif_pwd

# Kubectl commands

    kubectl get secret neo4j-credential -o jsonpath='{.data.neo4j-credential}' | base64 --d
ecode

