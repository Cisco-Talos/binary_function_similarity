FROM ubuntu:focal

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y git python3-pip 

RUN mkdir /code
COPY requirements.txt /code/
RUN pip install -r /code/requirements.txt

COPY digraph_instructions_embeddings.py /code/
COPY digraph_numerical_features.py /code/
COPY test_digraph_instructions_embeddings.py /code/
COPY test_digraph_numerical_features.py /code/
