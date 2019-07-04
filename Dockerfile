# Domain Controller Enticing Password Tripwire (DCEPT) - Dockerfile
FROM ubuntu:16.04
MAINTAINER James Bettke

ENV DEBIAN_FRONTEND noninteractive

# Set the default shell to bash inside the container
RUN rm /bin/sh && ln -sf /bin/bash /bin/sh

# Ensure we have the latest packages
RUN apt-get update && apt-get upgrade -yf

RUN apt-get install -y cron wget build-essential libssl-dev python-pip python-setuptools
RUN apt-get install -y tcpreplay

# Install dependencies for sniffer component
RUN apt-get install -y tshark python-dev libxml2-dev libxslt1-dev
RUN pip install pyshark-legacy
RUN pip install pyiface

# ============================== ALTERNATIVE 1 of 2 ============================== 
# Download community-enhanced version of John the Ripper password cracker
# Version must support krb5pa-sha1 
RUN wget -O /tmp/john.tar.gz http://www.openwall.com/john/j/john-1.8.0-jumbo-1.tar.gz

# Verify integrity of download
RUN sha1sum -c <<< '31c8246d3a12ab7fd7de0d1070dda4654f5397a7 /tmp/john.tar.gz'

# Extract John the Ripper source files
RUN mkdir /tmp/john && tar -xvf /tmp/john.tar.gz -C /tmp/john --strip-components=1

# ============================== ALTERNATIVE 2 of 2 ============================== 
# If already downloaded the John the Ripper password cracker
# ADD ./john-1.8.0-jumbo-1.tar.gz /tmp
# RUN mv /tmp/john-1.8.0-jumbo-1 /tmp/john

# ================================================================================ 

# Fix bug with GCC v5 when compiling JtR - May not be needed after 1.8.0 update
# https://github.com/magnumripper/JohnTheRipper/issues/1093
RUN sed -i 's/#define MAYBE_INLINE_BODY MAYBE_INLINE/#define MAYBE_INLINE_BODY/g' /tmp/john/src/MD5_std.c

# Compile John the Ripper from source
RUN cd /tmp/john/src && ./configure && make clean && make -s

RUN mkdir -p /opt/dcept/var
RUN cp /tmp/john/run/john /opt/dcept/john
RUN touch /opt/dcept/john.ini

# Copy DCEPT source code into the container
ADD ./dcept/server /opt/dcept
ARG dcept_cfg
ADD $dcept_cfg /opt/dcept/dcept.cfg

# Add a cron job to keep the container up-to-date (does not apply to DCEPT code)
RUN echo '0 0 * * * root apt-get update && apt-get upgrade -yf' > /etc/cron.d/update-cron
RUN chmod 0644 /etc/cron.d/update-cron
CMD cron; /opt/dcept/dcept.py 
