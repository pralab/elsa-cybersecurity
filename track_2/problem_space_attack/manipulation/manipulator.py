import logging
import os
from .manipulation_status import ManipulationStatus
from obfuscapk.tool import (
    Apktool, Zipalign, ApkSigner)
from .obfuscators import *
import uuid
from secml.parallel import parfor2
from .manipulation_space import Manipulations


# For the plugin system log only the error messages and ignore the log level
# set by the user.
logging.getLogger("yapsy").level = logging.ERROR
logging.getLogger("obfuscapk.tool.Apktool").setLevel(logging.CRITICAL)
logging.getLogger("obfuscapk.obfuscation").setLevel(logging.CRITICAL)


path = os.path.join(os.path.dirname(__file__), "lib")
os.environ["APKTOOL_PATH"] = os.path.join(path, "apktool")
os.environ["APKSIGNER_PATH"] = os.path.join(path, "apksigner")
os.environ["BUNDLE_DECOMPILER_PATH"] = os.path.join(
    path, "BundleDecompiler.jar")


def _apply_manipulations(i, manipulator, manipulations_list):
    manipulator.manipulation_status.obfuscated_apk_path = (
        manipulator.manipulated_apks_dir(
        f"{os.path.basename(manipulator._apk_path).split('.apk')[0]}_"
        f"{uuid.uuid1().hex}.apk"))
    manipulations = manipulations_list[i]
    try:
        manipulator._manipulate(manipulations, i)
        manipulator.manipulation_status.build_obfuscated_apk()
    except:
        manipulations = None
    finally:
        manipulator.manipulation_status.clean_iter(i)
        if os.path.exists(manipulator.manipulation_status.obfuscated_apk_path):
            os.remove(manipulator.manipulation_status.obfuscated_apk_path)
        return manipulations


class Manipulator:
    def __init__(self, apk_path, manipulated_apks_dir,
                 logging_level=logging.INFO):

        self._manipulated_apks_dir = manipulated_apks_dir

        # Logging configuration.
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(
            format="%(asctime)s> [%(levelname)s][%(name)s][%(funcName)s()] "
                   "%(message)s",
            datefmt="%d/%m/%Y %H:%M:%S",level=logging_level)

        self._check_external_tool_dependencies()
        self._apk_path = apk_path
        self._only_main_dex = False

        self.obfuscators = [
            AttClassRename(),
            AttAdvancedReflection(),
            AttConstStringEncryption(),
            ApiInjection(),
            StringInjection()
        ]

        self.manipulation_status = ManipulationStatus(
            apk_path, None, False, False,
            None, None, None, None,
            None, None, False)

        self._decode_apk()

    def _decode_apk(self):
        self.logger.debug("Decoding APK")
        try:
            self.manipulation_status.decode_apk()
        except Exception as e:
            self.clean_data()
            if os.path.exists(self.manipulation_status.obfuscated_apk_path):
                os.remove(self.manipulation_status.obfuscated_apk_path)
            try:
                self.logger.debug("Error while decoding APK: trying again"
                                  "considering only main dex files")
                self.manipulation_status.decode_apk(only_main_dex=True)
                self._only_main_dex = True
            except Exception as e:
                self.clean_data()
                if os.path.exists(self.manipulation_status.obfuscated_apk_path):
                    os.remove(self.manipulation_status.obfuscated_apk_path)
                self.logger.critical(
                    "Error during APK decoding: {0}".format(e), exc_info=True)
                raise

    def _check_external_tool_dependencies(self):
        """
        Make sure all the external needed tools are available and ready to be used.
        """
        # APKTOOL_PATH, APKSIGNER_PATH and ZIPALIGN_PATH environment variables can be
        # used to specify the location of the external tools (make sure they have the
        # execute permission). If there is a problem with any of the executables below,
        # an exception will be thrown by the corresponding constructor.
        self.logger.debug("Checking external tool dependencies")
        Apktool()
        ApkSigner()
        Zipalign()

    def manipulate(self, manipulations, i):
        obfuscated_apk_path = self.manipulated_apks_dir(
            f"{os.path.basename(self._apk_path).split('.apk')[0]}_"
            f"{uuid.uuid1().hex}.apk")
        self.manipulation_status.obfuscated_apk_path = obfuscated_apk_path
        try:
            self._manipulate(manipulations, i)
            self.manipulation_status.build_obfuscated_apk()
            self.manipulation_status.sign_obfuscated_apk()
            self.manipulation_status.align_obfuscated_apk()
        except Exception as e:
            self.logger.error("Error during APK manipulation: {0}".format(e))
            obfuscated_apk_path = None
        finally:
            self.manipulation_status.clean_iter(i)
            return obfuscated_apk_path

    def _manipulate(self, manipulations, i):
        self.manipulation_status.reset()
        self.manipulation_status.update_path(i)

        for feature in manipulations.inject:
            splitted_feat = feature.split("::")
            feat_type, feat = splitted_feat[0], splitted_feat[1]
            if feat_type == "urls":
                self.manipulation_status.urls_to_inject.add(feat)
            elif feat_type == "api_calls":
                self.manipulation_status.apis_to_inject.add(feat)


        for feature in manipulations.obfuscate:
            splitted_feat = feature.split("::")
            feat_type, feat = splitted_feat[0], splitted_feat[1]
            if feat_type == "urls":
                self.manipulation_status.string_to_encrypt.add(feat)
            elif feat_type == "api_calls" or feat_type == "suspicious_calls":
                self.manipulation_status.android_api_to_reflect.add(feat)
            elif feat_type in [
              "activities", "services", "providers", "receivers"]:
                self.manipulation_status.class_to_rename.add(
                    "L" + feat.replace(".", "/") + ";")

        for obfuscator in self.obfuscators:
            if obfuscator.is_adding_fields:
                self.manipulation_status.obfuscators_adding_fields += 1
            if obfuscator.is_adding_methods:
                self.manipulation_status.obfuscators_adding_methods += 1

        for obfuscator in self.obfuscators:
            obfuscator.obfuscate(self.manipulation_status)

    def clean_data(self):
        self.manipulation_status.clean_data()

    def get_error_free_manipulations(self, manipulations, n_jobs=1):

        self.logger.debug("Checking error-free manipulations")

        # test build without applying manipulations
        try:
            self.manipulation_status.build_obfuscated_apk()
        except Exception as e:
            self.clean_data()
            if os.path.exists(self.manipulation_status.obfuscated_apk_path):
                os.remove(self.manipulation_status.obfuscated_apk_path)
            try:
                self.logger.debug("Error during APK building: trying"
                                  "without decompiling resources"
                                  "and considering only main dex files")
                self.manipulation_status._is_decoded = False
                self.manipulation_status.decode_apk(
                    skip_resources=True, only_main_dex=self._only_main_dex)
                self.manipulation_status.build_obfuscated_apk()
                self.obfuscators = [o for o in self.obfuscators if not
                                    isinstance(o, AttClassRename)]
            except Exception as e:
                self.clean_data()
                self.logger.critical(
                    "The APK cannot be build: {0}".format(e))
                raise
        finally:
            if os.path.exists(self.manipulation_status.obfuscated_apk_path):
                os.remove(self.manipulation_status.obfuscated_apk_path)

        error_free_manipulations = Manipulations([], [])

        def _recurse_apply_manipulations(manipulations):
            if isinstance(manipulations, Manipulations):
                manipulations_list = [manipulations]
            else:
                manipulations_list = manipulations

            applied_manipulations_list = parfor2(
                _apply_manipulations, len(manipulations_list),
                n_jobs, self, manipulations_list)

            for applied_manipulations, manipulations in zip(
                    applied_manipulations_list, manipulations_list):
                if applied_manipulations is None:
                    if len(manipulations) > 1:
                        n = min(n_jobs, len(manipulations))
                        idxs = manipulations.get_idxs()
                        manipulations = [
                            manipulations.get_manipulations_from_vector(
                                idxs[i::n]) for i in range(n)]
                        _recurse_apply_manipulations(manipulations)
                else:
                    error_free_manipulations.inject.extend(
                        applied_manipulations.inject)
                    error_free_manipulations.obfuscate.extend(
                        applied_manipulations.obfuscate)

        _recurse_apply_manipulations(manipulations)

        return error_free_manipulations

    def manipulated_apks_dir(self, file):
        return os.path.join(self._manipulated_apks_dir, file)