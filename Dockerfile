FROM python:3.8-slim
LABEL org.opencontainers.image.source=https://github.com/hgokduman/spf-flattener
WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "-u", "./run.py" ]
