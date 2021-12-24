# vuln-log4j-webapp

Simple native Java webserver with minimal dependencies that uses a vulnerable Log4j version for logging.

No `gradle`, no `maven`, just `javac`, `java` and some `jar` files.

## How to build
```bash
docker build -t vuln-log4-webapp .
```

## How to run

```bash
docker run -it vuln-log4-webapp
```

The webapp now runs on port 8000 and you can use the `/test` endpoint.
```
Logging all SSL session keys to: /tmp/sslkeylog.txt
2021-12-23 11:58:16,736 DEBUG [main] App (App.java:24) - starting web server on port 8000
```

## What does it log

It logs different things to stdout using Log4j from the HTTP request:

 * HTTP method
 * Request URI
 * User-Agent header
 * username and password in Basic Authorization (base64 decoded)
 * Request body

When exploiting using `ldaps`, the TLS Client Random keys are written to `/tmp/sslkeylog.txt`
