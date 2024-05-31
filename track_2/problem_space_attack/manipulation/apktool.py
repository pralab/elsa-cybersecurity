#!/usr/bin/env python3

import logging
import os
import shutil
import subprocess
import tempfile
from typing import List


class Apktool_(object):
    def __init__(self):
        self.logger = logging.getLogger(
            "{0}.{1}".format(__name__, self.__class__.__name__)
        )

        if "APKTOOL_PATH" in os.environ:
            self.apktool_path: str = os.environ["APKTOOL_PATH"]
        else:
            self.apktool_path: str = "apktool"

        full_apktool_path = shutil.which(self.apktool_path)

        # Make sure to use the full path of the executable (needed for cross-platform
        # compatibility).
        if full_apktool_path is None:
            raise RuntimeError(
                'Something is wrong with executable "{0}"'.format(self.apktool_path)
            )
        else:
            self.apktool_path = full_apktool_path

    def decode(
        self, apk_path: str, output_dir_path: str = None, force: bool = False,
        skip_resources: bool = False, skip_code: bool = False,
        only_main_dex: bool = False
    ) -> str:
        # Check if the apk file to decode is a valid file.
        if not os.path.isfile(apk_path):
            self.logger.error('Unable to find file "{0}"'.format(apk_path))
            raise FileNotFoundError('Unable to find file "{0}"'.format(apk_path))

        # If no output directory is specified, use a new directory in the same
        # directory as the apk file to decode.
        if not output_dir_path:
            output_dir_path = os.path.join(
                os.path.dirname(apk_path),
                os.path.splitext(os.path.basename(apk_path))[0],
            )
            self.logger.debug(
                "No output directory provided, the result will be saved in the "
                "same directory as the input file, in a directory with the same "
                'name as the input file: "{0}"'.format(output_dir_path)
            )

        # If an output directory is provided, make sure that the path to that
        # directory exists (the final directory will be created by apktool).
        elif not os.path.isdir(os.path.dirname(output_dir_path)):
            self.logger.error(
                'Unable to find output directory "{0}", apktool won\'t be able to '
                'create the directory "{1}"'.format(
                    os.path.dirname(output_dir_path), output_dir_path
                )
            )
            raise NotADirectoryError(
                'Unable to find output directory "{0}", apktool won\'t be able to '
                'create the directory "{1}"'.format(
                    os.path.dirname(output_dir_path), output_dir_path
                )
            )

        # Inform the user if an existing output directory is provided without the
        # "force" flag.
        if os.path.isdir(output_dir_path) and not force:
            self.logger.error(
                'Output directory "{0}" already exists, use the "force" flag '
                "to overwrite".format(output_dir_path)
            )
            raise FileExistsError(
                'Output directory "{0}" already exists, use the "force" flag '
                "to overwrite".format(output_dir_path)
            )

        decode_cmd: List[str] = [
            self.apktool_path,
            "--frame-path",
            tempfile.gettempdir(),
            "d",
            apk_path,
            "-o",
            output_dir_path,
        ]

        if skip_resources:
            decode_cmd.insert(4, "--no-res")

        if skip_code:
            decode_cmd.insert(4, "--no-src")

        if only_main_dex:
            decode_cmd.insert(4, "--only-main-classes")

        if force:
            decode_cmd.insert(4, "--force")

        try:
            self.logger.info(
                'Running decode command "{0}"'.format(" ".join(decode_cmd))
            )
            # A new line character is sent as input since newer versions of Apktool
            # have an interactive prompt on Windows where the user should press a key.
            output = subprocess.check_output(
                decode_cmd, stderr=subprocess.STDOUT, input=b"\n"
            ).strip()
            if b"Exception in thread " in output:
                # Report exception raised in Apktool.
                raise subprocess.CalledProcessError(1, decode_cmd, output)
            return output.decode(errors="replace")
        except subprocess.CalledProcessError as e:
            self.logger.error(
                "Error during decode command: {0}".format(
                    e.output.decode(errors="replace") if e.output else e
                )
            )
            raise
        except Exception as e:
            self.logger.error("Error during decoding: {0}".format(e))
            raise
