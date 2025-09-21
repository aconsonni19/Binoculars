#!/usr/bin/env python
import sys

import angr
import logging

from pathlib import Path
from importlib import util

from arbiter.master_chief import *

class ArbiterAnalysis:
    def __init__(self, LOG_DIR = None, JSON_DIR = None, CALL_DEPTH = 1, STRICT_MODE = False, IDENTIFIER = None, CALLER_LEVEL = -1, BLACKLIST = None):
        self.LOG_DIR = LOG_DIR
        self.JSON_DIR = JSON_DIR
        self.CALL_DEPTH = CALL_DEPTH
        self.STRICT_MODE = STRICT_MODE
        self.IDENTIFIER = IDENTIFIER
        self.LOG_LEVEL = logging.DEBUG
        self.CALLER_LEVEL = CALLER_LEVEL
        self.BLACKLIST = BLACKLIST
        logging.getLogger('angr').setLevel(logging.CRITICAL)

    def __enable_logging(self, vd, target):
        vd = Path(vd).stem
        target = Path(target).stem

        loggers = ['sa_recon', 'sa_advanced', 'symbolic_execution']
        for logger in loggers:
            l = logging.getLogger(f"arbiter.master_chief.{logger}")

            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            if self.LOG_DIR is not None:
                handler = logging.FileHandler(f"{self.LOG_DIR}/arbiter_{vd}_{target}.log")
                handler.setFormatter(formatter)
                l.addHandler(handler)

            l.setLevel(self.LOG_LEVEL)

    def __setup(self, vd_path: str, target_path: str):
        vd = Path(vd_path)
        target = Path(target_path)

        if not vd.exists():
            sys.stderr.write(f"Error: {vd} does not exist\n")
            raise Exception("VD does not exist")
        elif not target.exists():
            sys.stderr.write(f"Error: {target} does not exist\n")
            raise Exception("Target does not exist")

        try:
            spec = util.spec_from_file_location(vd.stem, vd.absolute().as_posix())
            template = util.module_from_spec(spec)
            spec.loader.exec_module(template)
        except:
            sys.stderr.write(f"Error could not import VD: {vd}\n")
            raise Exception("Error importing the VD")

        if self.LOG_DIR:
            Path(self.LOG_DIR).mkdir(parents=True, exist_ok=True)
            if Path(self.LOG_DIR).exists():
                self.LOG_DIR = Path(self.LOG_DIR).resolve().as_posix()
            else:
                sys.stderr.write(f"Directory {self.LOG_DIR} does not exist and we could not create it\n")
        self.__enable_logging(vd, target)

        if self.JSON_DIR:
            Path(self.JSON_DIR).mkdir(parents=True, exist_ok=True)
            if Path(self.JSON_DIR).exists():
                self.JSON_DIR = Path(self.JSON_DIR).resolve().as_posix()
            else:
                sys.stderr.write(f"Directory {self.JSON_DIR} does not exist and we could not create it\n")

        return template, target

    def analyze(self, vd, target):
        project = angr.Project(target, auto_load_libs=False)

        template, target = self.__setup(vd, target)

        sink_map = template.specify_sinks()
        sa = SA_Recon(project, sinks=sink_map.keys(), maps=sink_map, json_dir=self.JSON_DIR)
        if self.IDENTIFIER is None:
            sa.analyze(ignore_funcs=self.BLACKLIST)
        else:
            sa.analyze_one(self.IDENTIFIER)

        sources = template.specify_sources()
        sb = SA_Adv(sa, checkpoint=sources, require_dd=self.STRICT_MODE, call_depth=self.CALL_DEPTH, json_dir=self.JSON_DIR)
        sb.analyze_all()

        constrain = template.apply_constraint
        se = SymExec(sb, constrain=constrain, require_dd=self.STRICT_MODE, json_dir=self.JSON_DIR)
        se.run_all()

        template.save_results(se.postprocessing(pred_level=self.CALLER_LEVEL))


