FROM python:3.11-slim

WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /usr/src/app/

EXPOSE 4000

CMD ["python3", "manage.py", "runserver", "0.0.0.0:4000"]
