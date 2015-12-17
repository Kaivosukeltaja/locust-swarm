#!/usr/bin/env bash

if [ -n "$(command -v yum)" ]
then
  # TODO: Install python and pip if your AMI doesn't include them already
  sudo yum install gcc gcc-c++ make openssl-devel -y
  sudo yum install git -y
  sudo pip install --upgrade pip
  # TODO: The upgrade may screw up the directory of PIP for some reason
  sudo /usr/local/bin/pip install -r /tmp/locust/bootstrap-slave/requirements.txt
elif [ -n "$(command -v apt-get)" ]
then
  sudo apt-get update -y
  sudo apt-get upgrade -y
  sudo apt-get install python -y
  sudo apt-get install python-pip -y
  sudo apt-get install python-dev -y
  sudo apt-get install build-essential -y
  sudo apt-get install git -y
  sudo apt-get install libevent-dev -y
  sudo pip install --upgrade pip
  sudo pip install -r /tmp/locust/bootstrap-slave/requirements.txt
else
  echo "Error: Can't find either yum or apt-get!"
  echo "Please modify bootstrap.sh to support your weird package manager."
fi