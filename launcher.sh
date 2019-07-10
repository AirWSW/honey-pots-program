#!/bin/bash

# Set working directory to script directory 
cd "$(dirname "$(readlink -f "$0")")"

# Build a Docker image and tag it "dcept"
docker build --build-arg dcept_cfg="./config/dcept.cfg" -t dcept .

CONTAINER=$(docker ps -aqf name=dcept)

if [ -n "$CONTAINER" ]; then
	echo "Stopping container named dcept"
	docker stop dcept 1>/dev/null
	echo "Removing container named dcept"
	docker rm dcept 1>/dev/null
fi

if [ -z "$1" ]; then
	arg="-it"
	
else
	arg="-d"
fi

echo "Starting container..."
# docker run $arg --name dcept --cap-add=NET_ADMIN -p 80:8080 --net=host -v `pwd`/volume:/opt/dcept/var dcept
docker run $arg --rm --name=dcept_master --net=host -v `pwd`/volume:/opt/dcept/var dcept

if [ -n "$1" ]; then
	CONTAINER=$(docker ps -q -f name=dcept) 
	echo "Running DCEPT docker container:" $CONTAINER
	echo 
	docker ps -f name=dcept
	echo -e "\nTo the stop the container run the following command:\n\tdocker stop dcept"
fi
