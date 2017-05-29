#!/usr/bin/env bash

cp ./common/queue_worker.py ./queue_worker.py

python -u queue_worker.py &

# gunicorn --config=gunicorn.py user_service:app
python -u user_service.py