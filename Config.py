import tomllib
from functools import reduce
import operator

class Config():
    def __init__(self, cfg_file = "./config.toml"):
        # Open config file
        try:
            with open(cfg_file, "rb") as f:
                self.cfg = tomllib.load(f)
                assert self.cfg

        except IOError as e:
            print(e)
            exit(1)

    def get(self, path):
        path_list = path.split('/')
        return reduce(operator.getitem, path_list, self.cfg)