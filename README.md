# postkit-notes

Multi-tenant notes app demonstrating [Postkit](https://github.com/varunchopra/postkit) for auth, permissions, metering, and config.

## Quick Start

```bash
make up
```

Opens at http://localhost:5001

Requires Docker, Docker Compose, and Make.

## Development

```bash
make up      # start containers
make down    # stop containers
make clean   # remove volumes
```

## How It Works

The Dockerfile clones postkit and builds SQL schemas. Docker Compose runs two services: a Postgres container initialized with those schemas plus `init-app.sql`, and a Flask app using the postkit Python SDK.

## API Usage

### Authentication

Login to get tokens:
```bash
curl -X POST http://localhost:5001/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "yourpassword"}'
```

List your organizations:
```bash
curl http://localhost:5001/api/orgs \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Make requests with org context:
```bash
curl http://localhost:5001/api/notes \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "X-Org-Id: YOUR_ORG_ID"
```

### API Key Authentication

Create an API key in the dashboard, then:
```bash
curl http://localhost:5001/api/notes \
  -H "Api-Key: pk_YOUR_API_KEY" \
  -H "X-Org-Id: YOUR_ORG_ID"
```

## License

Apache 2.0
