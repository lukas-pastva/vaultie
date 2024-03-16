FROM python:3.8-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir flask hvac==2.1.0

EXPOSE 5000

ENV FLASK_APP=app.py

CMD ["flask", "run", "--host=0.0.0.0"]
