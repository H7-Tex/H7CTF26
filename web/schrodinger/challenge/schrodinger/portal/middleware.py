from starlette.responses import JSONResponse

from schrodinger.config import MAX_UPLOAD_BYTES


class UploadLimitMiddleware:
    """Bound raw multipart buffering, including requests without Content-Length."""

    max_request_bytes = MAX_UPLOAD_BYTES + 64 * 1024

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope["method"] != "POST"
            or scope["path"] not in {"/api/packages", "/api/v1/packages"}
        ):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                if int(raw_length) > self.max_request_bytes:
                    await JSONResponse({"detail": "upload exceeds the 20 MiB limit"}, status_code=413)(scope, receive, send)
                    return
            except ValueError:
                await JSONResponse({"detail": "invalid Content-Length"}, status_code=400)(scope, receive, send)
                return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.max_request_bytes:
                await JSONResponse({"detail": "upload exceeds the 20 MiB limit"}, status_code=413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        buffered_body = bytes(body)
        delivered = False

        async def buffered_receive():
            nonlocal delivered
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": buffered_body, "more_body": False}

        await self.app(scope, buffered_receive, send)
