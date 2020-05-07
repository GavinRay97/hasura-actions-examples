FROM python:3.8-alpine

EXPOSE 5000

WORKDIR /app

COPY * /app/

RUN apk add --no-cache gcc g++ make libffi-dev python3-dev

RUN pip install -r requirements.txt

CMD python app.py