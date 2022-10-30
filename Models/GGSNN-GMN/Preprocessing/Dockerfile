FROM ubuntu:focal

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y git python3-pip 

RUN mkdir /code
COPY requirements.txt /code/
RUN pip install -r /code/requirements.txt

COPY gnn_preprocessing.py /code/
COPY test_gnn_preprocessing.py /code/
