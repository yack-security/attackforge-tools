# Yack AttackForge Tooling

## Overview

This project is a non exhaustive list of tools made by [Yack](https://yack.one) for interacting with the [AttackForge](https://attackforge.com) REST API and events API.

1. Cloudflare worker for ssapi-events.
2. Python library for interacting with the AttackForge REST API.

## Cloudflare Worker

The Cloudflare worker is used to listen to ssapi-events and process them. It is a simple worker that listens to the ssapi-events endpoint and processes the events.

You can find the original nodejs client [here](https://github.com/AttackForge/afe-ssapi-events-nodejs-client).

### Setup Cloudflare worker

You will need wrangler installed to deploy the worker.

```bash
git clone https://github.com/yack-security/attackforge-tools.git
cd attackforge-tools/workers/attackforge-events-worker

# create a KV namespace
wrangler kv:namespace create WORKER_STATE

# copy the example file and edit it with your own values
cp wrangler.jsonc.example wrangler.jsonc

# deploy the worker
npm i
npm run deploy

# add your API key as secret
wrangler secret put X_SSAPI_KEY
```

You can now check the worker logs to ensure it is working.

```bash
wrangler logs --tail
```

## Python Library

The python library is used to interact with the AttackForge API. It is a small library that provides a simple interface for interacting with the AttackForge API.

### Setup python library

```bash
git clone https://github.com/yack-security/attackforge-tools.git
cd attackforge-tools

# install the dependencies
pip install -r requirements.txt

# copy the example file and edit it with your own values
cp .env.example .env
```

Use the library in your own project.

```python
import lib.af_lib as af_lib

# verify that you have access to the API
af_access = af_lib.verify_af_access()
# print(af_access)

# use any API GET endpoint
url = af_lib.build_url("projects")
response = af_lib.fetch_af(url)
# print(response)

# use any API POST endpoint
url = af_lib.build_url("vulnerability-with-library")
payload = {
    "your_field": "your_value",
    # ...
}
response = af_lib.post_af(url, payload)
# print(response)

# use any API PUT endpoint
url = af_lib.build_url("project/your_project_id")
payload = {
    "your_field": "your_value",
    # ...
}
response = af_lib.put_af(url, payload)
# print(response)

# send an email
payload = {
    "to": ["your_email@example.com"],
    # "to": ["your_email@example.com", {"user_id": "your_user_id"}],
    "cc": ["your_cc_email@example.com"],
    "subject": "Your Subject",
    "text": "Your Email Body",
    # "html": "&lt;p style=\"border: 3px solid green;\"&gt;&lt;b&gt;Your Email Body&lt;/b&gt;&lt;/p&gt;"
}
response = af_lib.send_email_af(payload)
# print(response)

# export project data
project_id = "your_project_id"
data = af_lib.export_project_data(project_id)
# print(data)

# you can see all functions in the library by looking at the lib/af_lib.py file
```

## Credits

- [AttackForge](https://attackforge.com) for building this amazing platform.
