
"""
Ping Pong PoC Server (Flask)
"""

import os
import random
import string
import sys
from http import HTTPStatus
from typing import Dict

from flask import Flask, Response, request

# Add include directory to path to import malleable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "include"))

from openmalleable import MalleableProfile, MalleableServer, HttpRequest, ProfileMismatchError

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

app = Flask(__name__)
_COLOR_BLUE = "\033[34m"
_COLOR_RED = "\033[31m"
_COLOR_RESET = "\033[0m"
_malleable_server: MalleableServer | None = None
_current_challenge: str | None = None


def print_banner(title: str) -> None:
    print("=" * 60)
    print(title)
    print("=" * 60)


def _log(message: str) -> None:
    print(message, flush=True)


def _log_colored(message: str, color: str) -> None:
    if getattr(sys.stdout, "isatty", lambda: False)():
        _log(f"{color}{message}{_COLOR_RESET}")
    else:
        _log(message)


def _format_request_text(http_request: HttpRequest) -> str:
    request_line = f"{http_request.method} {request.full_path or request.path} HTTP/1.1"
    lines = [request_line]
    for key, value in request.headers.items():
        lines.append(f"{key}: {value}")
    lines.append("")
    if http_request.body:
        body_text = http_request.body.decode("utf-8", errors="replace")
        lines.append(body_text)
    return "\r\n".join(lines)


def _format_response_text(status_code: int, headers: Dict[str, str], body: bytes) -> str:
    reason = HTTPStatus(status_code).phrase if status_code in HTTPStatus._value2member_map_ else ""
    status_line = f"HTTP/1.1 {status_code} {reason}".rstrip()
    lines = [status_line, f"Content-Length: {len(body) if body else 0}"]
    for key, value in headers.items():
        lines.append(f"{key}: {value}")
    lines.append("")
    if body:
        body_text = body.decode("utf-8", errors="replace")
        lines.append(body_text)
    return "\r\n".join(lines)


def _to_http_request() -> HttpRequest:
    query_dict = {k: v for k, v in request.args.items()}
    headers_dict = {k: v for k, v in request.headers.items()}
    body = request.get_data(cache=True) or b""
    host = headers_dict.get("Host", "127.0.0.1:8080")
    uri = f"http://{host}{request.full_path or request.path}"

    return HttpRequest(
        method=request.method,
        uri=uri,
        path=request.path,
        query=query_dict,
        headers=headers_dict,
        body=body,
    )


def _send_response(status_code: int, headers: Dict[str, str], body: bytes) -> Response:
    response = Response(body or b"", status=status_code)
    response.headers["Content-Length"] = str(len(body) if body else 0)
    for key, value in headers.items():
        response.headers[str(key)] = str(value)
    return response


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def handle(path: str):
    global _current_challenge
    if _malleable_server is None:
        _log("[Server] Malleable server not initialized.")
        return _send_response(500, {}, b"")

    _log(f"\n[DEBUG] {request.method} request received!",)
    http_request = _to_http_request()
    _log_colored("[DEBUG] Raw HTTP request:\n" + _format_request_text(http_request), _COLOR_BLUE)

    _log("\n" + "=" * 60)
    _log(f"[Server] Received {request.method} {http_request.path}")
    _log("=" * 60)

    try:
        if request.method == "GET":
            metadata = _malleable_server.extract_metadata(http_request, "default")
            _log(f"[Server] Extracted metadata ({len(metadata)} bytes):")
            _log(f"[Server] {metadata.decode('utf-8', errors='ignore')}")

            random_challenge = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            _current_challenge = random_challenge

            tasks = random_challenge.encode('utf-8')

            _log(f"[Server] Generated challenge: {random_challenge}")
            _log(f"[Server] Sending task ({len(tasks)} bytes):")
            _log(f"[Server] \"{random_challenge}\"")

            response_obj = _malleable_server.build_get_response(tasks, "default")
            response_headers = {k: v for k, v in response_obj.headers.items()}
            body = response_obj.body or b""
            _log_colored(
                "[DEBUG] Raw HTTP response:\n" + _format_response_text(response_obj.status_code, response_headers, body),
                _COLOR_RED,
            )
            return _send_response(response_obj.status_code, response_headers, body)

        session_id = _malleable_server.extract_session_id(http_request, "default")
        output = _malleable_server.extract_output(http_request, "default")

        _log(f"[Server] Extracted session ID ({len(session_id)} bytes):")
        _log(f"[Server] {session_id.decode('utf-8', errors='ignore')}")
        _log(f"[Server] Extracted task output ({len(output)} bytes):")
        _log(f"[Server] {output.decode('utf-8', errors='ignore')}")

        output_str = output.decode('utf-8', errors='ignore')

        if _current_challenge:
            reversed_challenge = _current_challenge[::-1]
            _log(f"[Server] Original challenge: {_current_challenge}")
            _log(f"[Server] Expected reversed:  {reversed_challenge}")

            if reversed_challenge in output_str:
                _log(f"[Server] SUCCESS! Verified reversed challenge in output")
                confirmation = (
                    "CONFIRMED: Task completed successfully! Received reversed string correctly"
                ).encode('utf-8')
            else:
                _log(f"[Server] WARNING: Reversed challenge '{reversed_challenge}' not found in output")
                _log(f"[Server] Received: {output_str}")
                confirmation = b"CONFIRMED: Output received (verification failed)"
        else:
            _log(f"[Server] WARNING: No challenge set")
            confirmation = b"CONFIRMED: Output received (no challenge)"

        _log(f"[Server] Sending confirmation ({len(confirmation)} bytes)")

        response_obj = _malleable_server.build_post_response(confirmation, "default")
        response_headers = {k: v for k, v in response_obj.headers.items()}
        body = response_obj.body or b""
        _log_colored(
            "[DEBUG] Raw HTTP response:\n" + _format_response_text(response_obj.status_code, response_headers, body),
            _COLOR_RED,
        )
        return _send_response(response_obj.status_code, response_headers, body)
    except ProfileMismatchError as exc:
        _log(f"[Server] UNKNOWN REQUEST DID NOT MATCH PROFILE! {exc}")
        _log_colored("[DEBUG] Raw HTTP response:\nHTTP/1.1 404 Not Found\r\n\r\n", _COLOR_RED)
        return _send_response(404, {}, b"")
    except Exception as exc:
        _log(f"[Server] Error handling {request.method}: {exc}")
        import traceback

        traceback.print_exc()
        _log_colored("[DEBUG] Raw HTTP response:\nHTTP/1.1 500 Internal Server Error\r\n\r\n", _COLOR_RED)
        return _send_response(500, {}, b"")


def main() -> None:
    global _malleable_server
    if len(sys.argv) != 2:
        print("Usage: python pingpong_server.py <profile.profile>")
        sys.exit(1)

    profile_path = sys.argv[1]
    print_banner("Ping Pong PoC Server")
    print(f"[Server] Reading profile file: {profile_path}")

    with open(profile_path, 'r') as f:
        profile_content = f.read()

    print(f"[Server] Parsing profile from memory...")
    profile = MalleableProfile(profile_content)
    _malleable_server = MalleableServer(profile)

    print(f"[Server] Profile loaded: {profile.profile_name}")
    print(f"[Server] User-Agent: {profile.useragent}")
    print("[Server] Listening on http://127.0.0.1:8080")
    print("[Server] Waiting for agent check-in...")

    app.run(host="127.0.0.1", port=8080, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
