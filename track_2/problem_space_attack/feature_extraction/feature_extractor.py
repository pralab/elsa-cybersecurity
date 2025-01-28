from feature_extraction.base_feature_extractor import BaseFeatureExtractor
from .apk_analyzer import process_apk
import logging
import os
import json


class FeatureExtractor(BaseFeatureExtractor):
    """
    Feature extractor used in the problem-space attack
    """

    def __init__(self, logging_level=logging.INFO):
        """

        Parameters
        ----------
        logging_level : int
            Set the verbosity of the logger.
        """
        super(FeatureExtractor, self).__init__()
        self._set_logger(logging_level)

    def _extract_features(self, apk):
        if self._features_out_dir is not None:
            file_name = os.path.join(
                self._features_out_dir,
                os.path.splitext(os.path.basename(apk))[0] + ".json")
            if os.path.exists(file_name):
                self.logger.info(f"feature for {apk} were already extracted")
                with open(file_name, "r") as js:
                    data = json.load(js)
                    return [f"{k}::{v}" for k in data
                            for v in data[k] if data[k]]
        if os.path.exists(apk) and os.path.getsize(apk) > 0:
            result = process_apk(apk, self._features_out_dir, self.logger)
            self.logger.info(f"{apk} features were successfully extracted")
            return result
        else:
            self.logger.error(f"{apk} does not exist or is an empty file")
        return None

    def _set_logger(self, logging_level):
        logging.basicConfig(
            level=logging_level, datefmt="%Y/%m/%d %H:%M:%S",
            format="%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s: "
                   "%(message)s")
        error_handler = logging.StreamHandler()
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(
            logging.Formatter("%(asctime)s %(filename)s[line:%(lineno)d] "
                              "%(levelname)s: %(message)s"))
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(error_handler)
        logging.getLogger("androguard.dvm").setLevel(logging.CRITICAL)
        logging.getLogger("androguard.core.api_specific_resources").setLevel(
            logging.CRITICAL)
        logging.getLogger("androguard.axml").setLevel(logging.CRITICAL)
        logging.getLogger("androguard.apk").setLevel(logging.CRITICAL)
