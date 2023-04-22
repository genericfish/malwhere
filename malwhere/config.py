import json
import operator
from functools import reduce
from pathlib import Path

class Config:
    def __init__(self, cfg_file="./config.json"):
        # Open config file
        try:
            with open(cfg_file, "rb") as f:
                self.cfg = json.load(f)
                assert self.cfg

        except IOError as e:
            print(e)
            exit(1)

    def get(self, path):
        path_list = path.split("/")
        return reduce(operator.getitem, path_list, self.cfg)

    def get_path(self, path):
        return Path(self.get(path))
