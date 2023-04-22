import os
import time
import hashlib
import flask
import json
import subprocess
import base64

from pathlib import Path
from functools import partial
from flask import Flask, request, redirect, render_template, url_for
from Config import Config


# Load config
cfg = Config()

# Path to Ghidra installation
ghidra_path = Path(cfg.get("ghidra/path"))

# Path to Ghidra analysis output
analysis_path = Path(cfg.get("analysis/output"))
analysis_path.mkdir(parents=True, exist_ok=True)

# Get path to Ghidra project, make dirs if not exist
project_path = Path(cfg.get("ghidra/project/path"))
project_path.mkdir(parents=True, exist_ok=True)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(12).hex()

binary_path = partial(Path, cfg.get("binary/output"))
binary_path().mkdir(parents=True, exist_ok=True)

def get_ghidra_command(*args):
    command = [
        ghidra_path.joinpath("./support", "analyzeHeadless").absolute(),
        project_path.absolute(),
        cfg.get("ghidra/project/name")
    ]

    command += args

    command = map(str, command)

    return ' '.join(command)

def timestamp_ms():
    return round(time.time() * 1000)


def flash(message, category="error", redirect_url="/", code=302):
    flask.flash(message, category)

    return redirect(redirect_url, code)


@app.route("/")
def start_page():
    return render_template("start.html")


@app.route("/upload", methods=["POST", "GET"])
def upload():
    if request.method == "GET":
        return redirect("/")

    # Get binary file
    binary = request.files.get('binary')

    # If None, redirect
    if not binary:
        return redirect('/')

    # Get bytes of uploaded file
    binary_bytes = binary.stream.read()

    # Check if ELF or PE executable
    if binary_bytes[:4] != b'\x7fELF' and binary_bytes[:2] != b'\x5A\x40':
        return flash("Invalid file type")

    # Create 256-bit SHA3 hash of the uploaded binary
    binary_hash = base64.urlsafe_b64encode(hashlib.sha3_256(binary_bytes).digest()).decode('ascii')[:12]

    # Save binary file
    path = binary_path(binary_hash).absolute()

    # TODO: Ask user to confirm reanalyse of file that already exists
    if not path.exists():
        binary.stream.seek(0);
        binary.save(path)

    # FIXME: Use server-sent events via flask-sse to have the user load into a
    #        waiting page as Ghidra analyses a file, then callback when done.
    analyze_binary(path)

    return redirect(url_for('.analysis', submission_id=binary_hash))


@app.route("/analysis/<submission_id>")
def analysis(submission_id):
    funcs = analysis_path.joinpath(f"{submission_id}.json").absolute()
    functions = None

    with open(funcs, "r") as data:
        functions = json.load(data)

    return render_template("analysis.html", submission_id=submission_id, functions=functions)


def analyze_binary(abs_path_to_binary):
    script_path = Path(cfg.get("ghidra/script/path")).absolute()
    scripts = cfg.get("ghidra/script/files")

    if type(scripts) == str:
        scripts = [scripts]

    # TODO: Containerize this shit
    command = get_ghidra_command(
        "-import", abs_path_to_binary,
        "-scriptPath", script_path,
        *["-postScript " + script for script in scripts],
        "-overwrite"
    )

    print(f"Running subprocess with command: \"{command}\"")

    env = os.environ.copy()
    env["MALWHERE_ANALYSIS_PATH"] = str(analysis_path.absolute())

    subprocess.run(command, shell=True, env=env)