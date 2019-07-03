# honey-pots-program

### Building the Docker Image

```bash
docker-compose build
```

### Running the Docker Image as a Container

Run the Docker container interactively with the following command:
```bash
docker-compose up 
```

Run the container in the  background with the following command:
```bash
docker-compose up -d
```

### Testing

Run the following command to get an interactive shell inside the container.

```bash
docker exec -it CONTAINER_NAME bash
```

tcpreplay is installed inside the docker container along with a sample pcap for testing purposes. While DCEPT is running, execute the following from within the container:

```bash
tcpreplay -i <interface> /opt/dcept/example.pcap
```