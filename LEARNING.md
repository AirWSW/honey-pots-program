# linux kernel based system

```bash
sudo su chmod passwd
ls ll cat mv cp rm mkdir sed touch echo
vi vim nano
(du df fdisk)
systemctl service daemon cron
sshd
make 
docker dockerd
ping tracepath(traceroute/tracert) ip
wget curl
man
tar
pip
```

## debian 

```bash
apt [install/update/upgrade]
apt-get [install/update/upgrade]
```

## red hat

```bash
yum [install/update/upgrade/makecache]
dnf [install/update/upgrade/makecache]
(firewall-cmd) 
```

# docker

```
docker run -d -it --rm -p -v -t --host --name -d --restart --hostname \
           --net --ip --ip6 --mac-address --dns --memory --memory-swap \
           --oom-kill-disable --cpuset-cpus --cpu-shares --link -e
docker exec -it CNAME bash
docker ps
docker build -t TAG .
docker image[s]
docker network [inspect/rm/ls]
```

daemon.json

## Dockerfile

```docker
FROM LABLE ADD RUN ARG ENV CMD MAINTAINER COPY USER SHELL WORKDIR
```

## docker-compose

yml/yaml

```bash
docker-compose up --build
docker-compose down
```

# python

debug the dcept server [master&slave]

# .NET

debug/recode the agent 
