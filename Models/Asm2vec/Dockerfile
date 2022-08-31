FROM ubuntu:focal

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y git python3-pip 

RUN mkdir /code
COPY requirements.txt /code/
RUN pip install -r /code/requirements.txt

COPY i2v.py /code/
COPY i2v_preprocessing.py /code/
COPY asm2vec.patch /code/

WORKDIR /code/

RUN git clone https://github.com/RaRe-Technologies/gensim/ && \
	( cd gensim ; git checkout e889fa3d45a406cabbc7e180fa9a8ee3f76ac6f0 ; patch -s -p0 < ../asm2vec.patch ) && \
	pip3 install gensim/
