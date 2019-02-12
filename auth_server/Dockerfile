FROM python:2.7

EXPOSE 65010/tcp

WORKDIR /project

COPY RedditAPI.py /project
COPY server.py /project

ARG CLIENT_ID
ENV CLIENT_ID="$CLIENT_ID"

RUN test -n "$CLIENT_ID"

RUN pip install flask requests --user

CMD python /project/server.py