import os
import subprocess
from pathlib import Path

class Ghidra:
    def __init__(self, cfg):
        self.cfg = cfg

        # Path to Ghidra installation
        self.ghidra_path = cfg.get_path("ghidra/path")


        # Path to Ghidra analysis output
        self.analysis_path = cfg.get_path("analysis/output")
        self.analysis_path.mkdir(parents=True, exist_ok=True)

        # Get path to Ghidra project, make dirs if not exist
        self.project_path = cfg.get_path("ghidra/project/path")
        self.project_path.mkdir(parents=True, exist_ok=True)

    def get_ghidra_command(self, *args):
        command = [
            self.ghidra_path.joinpath("./support", "analyzeHeadless").absolute(),
            self.project_path.absolute(),
            self.cfg.get("ghidra/project/name"),
        ]

        command += args

        command = map(str, command)

        return " ".join(command)

    def analyze(self, abs_path_to_binary):
        script_path = Path(self.cfg.get("ghidra/script/path")).absolute()
        scripts = self.cfg.get("ghidra/script/files")

        if type(scripts) == str:
            scripts = [scripts]

        # TODO: Containerize this shit
        command = self.get_ghidra_command(
            "-import", abs_path_to_binary,
            "-scriptPath", script_path,
            *["-postScript " + script for script in scripts],
            "-overwrite",
        )

        print(f'[malwhere] Running subprocess with command: {command!r}')

        env = os.environ.copy()
        env["MALWHERE_ANALYSIS_PATH"] = str(self.analysis_path.absolute())

        subprocess.Popen(command, close_fds=True, shell=True, env=env)
