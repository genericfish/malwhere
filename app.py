import os
import time
import hashlib
import flask
import json
import base64

from pathlib import Path
from functools import partial
from flask import Flask, request, redirect, render_template, url_for, jsonify

from malwhere import Config, Ghidra


# Load config
cfg = Config()

# Initialize Flask app
app = Flask(__name__, static_url_path="/static")
app.secret_key = os.urandom(12).hex()

binary_path = partial(Path, cfg.get("binary/output"))
binary_path().mkdir(parents=True, exist_ok=True)

ghidra = Ghidra(cfg)


def timestamp_ms():
    return round(time.time() * 1000)


def flash(message, category="error", redirect_url="/", code=302):
    flask.flash(message, category)

    return redirect(redirect_url, code)


@app.route("/")
def start_page():
    return render_template("start.html")


@app.route("/upload/url", methods=["POST", "GET"])
def upload_url():
    if request.method == "GET":
        return redirect("/")

    return flash("Not yet implemented")

@app.route("/upload/file", methods=["POST", "GET"])
def upload_file():
    if request.method == "GET":
        return redirect("/")

    # Get binary file
    binary = request.files.get("binary")

    # If None, redirect
    if not binary:
        return redirect("/")

    # Get bytes of uploaded file
    binary_bytes = binary.stream.read()

    # Check if ELF or PE executable
    if binary_bytes[:4] != b"\x7fELF" and binary_bytes[:2] != b"\x5A\x40":
        return flash("Invalid file type")

    # Create 256-bit SHA3 hash of the uploaded binary
    binary_hash = base64.urlsafe_b64encode(
        hashlib.sha3_256(binary_bytes).digest()
    ).decode("ascii")[:12]

    # Save binary file
    path = binary_path(binary_hash).absolute()

    # TODO: Ask user to confirm reanalyse of file that already exists
    if not path.exists():
        binary.stream.seek(0)
        binary.save(path)

    analysis_file = ghidra.analysis_path.joinpath(f"{binary_hash}.json")
    if analysis_file.exists():
        os.remove(analysis_file.absolute())

    # FIXME: Use server-sent events via flask-sse to have the user load into a
    #        waiting page as Ghidra analyses a file, then callback when done.
    ghidra.analyze(path)

    return redirect(url_for(".analysis", submission_id=binary_hash))


@app.route("/analysis/<submission_id>")
def analysis(submission_id):
    analysis_file_path = ghidra.analysis_path.joinpath(f"{submission_id}.json")

    print(f"analysis_file_path {analysis_file_path!r}")
    if analysis_file_path.exists():
        functions = None

        with open(analysis_file_path.absolute(), "r") as data:
            functions = json.load(data)

        return render_template(
            "analysis.html", submission_id=submission_id, functions=functions
        )

    return render_template("loading.html", submission_id=submission_id)


@app.route("/api/1.0/exists/<submission_id>")
def api_exists(submission_id):
    analysis_file_path = ghidra.analysis_path.joinpath(f"{submission_id}.json")

    resp = {"exists": analysis_file_path.exists()}

    return jsonify(resp)
