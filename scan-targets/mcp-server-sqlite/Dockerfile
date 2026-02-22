FROM python:3.12-slim

RUN pip install mcp-server-sqlite

RUN mkdir -p /data

COPY init_db.py /tmp/init_db.py
RUN python3 /tmp/init_db.py && rm /tmp/init_db.py

ENTRYPOINT ["mcp-server-sqlite", "--db-path", "/data/test.db"]
