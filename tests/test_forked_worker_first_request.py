import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# The parent serves requests (its regex worker threads start), pauses, and forks;
# the child serves the same requests through the same app. A fresh interpreter keeps
# the test process, with its own threads and loop, from being forked.
_SCRIPT = """
import ast, os, time, logging, warnings
warnings.simplefilter("ignore"); logging.disable(logging.CRITICAL)
from flask import Flask
from flaskapi_guard import SecurityConfig
from flaskapi_guard.extension import FlaskAPIGuard
from guard_core.sync.handlers.suspatterns_handler import active_sus_patterns

config = SecurityConfig(enable_redis=False, enable_rate_limiting=False)
app = Flask(__name__)

@app.get("/p")
def probe():
    return {"ok": True}

FlaskAPIGuard(app, config=config)
texts = ("hello world", "zz-foo12bar-zz", "x' UNION SELECT password FROM users--")

def statuses():
    client = app.test_client()
    peer = {"REMOTE_ADDR": "203.0.113.9"}
    return [
        client.get("/p", query_string={"q": t}, environ_overrides=peer).status_code
        for t in texts
    ]

statuses()
active_sus_patterns().add_pattern(r"foo\\d+bar", True)
parent = statuses()
time.sleep(0.3)
reader, writer = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(reader)
    os.write(writer, repr(statuses()).encode())
    os._exit(0)
os.close(writer)
child = ast.literal_eval(os.read(reader, 65536).decode())
os.waitpid(pid, 0)
print(repr((parent, child)))
"""


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_a_forked_worker_answers_its_first_requests_like_its_parent() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"
    result = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", _SCRIPT],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=True,
    )
    parent, child = ast.literal_eval(result.stdout.strip().splitlines()[-1])

    assert parent[0] == 200
    assert parent[1:] == [400, 400]
    assert child == parent
