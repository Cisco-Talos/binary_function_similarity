FROM continuumio/miniconda3

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y git python3-pip

RUN mkdir /code
RUN git clone https://github.com/CUMLSec/trex /code/trex

WORKDIR /code/trex
RUN git checkout 7b2cabaecdaeb043da48d85a9016fed391ea75a5
RUN conda create -n trex python=3.8 numpy scipy scikit-learn requests

SHELL ["conda", "run", "-n", "trex", "/bin/bash", "-c"]

RUN conda install pytorch torchvision torchaudio cudatoolkit=11.1 -c pytorch -c nvidia
RUN pip install --editable .
RUN pip install click==8.0.4 && pip install pandas==1.4.2 && pip install gdown==4.4.0

COPY gdrive_model_download.py /code/trex
RUN python3 gdrive_model_download.py

COPY trex_inference.py /code/trex