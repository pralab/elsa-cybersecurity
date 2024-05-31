import os
from obfuscapk.obfuscation import Obfuscation
from obfuscapk import util
from memory_tempfile import MemoryTempfile
from shutil import rmtree, copytree
from .apktool import Apktool_
from obfuscapk.toolbundledecompiler import BundleDecompiler


class ManipulationStatus(Obfuscation):
    """This class contains the references to the APK, the methods for
    decompiling/recompiling it, and the status of the changes to be made.
    A single object is passed from the attack to the various obfuscators
    """

    def __init__(
            self,
            apk_path: str,
            obfuscated_apk_path: str = None,
            ignore_libs: bool = False,
            interactive: bool = False,
            virus_total_api_key: str = None,
            keystore_file: str = None,
            keystore_password: str = None,
            key_alias: str = None,
            key_password: str = None,
            ignore_packages_file: str = None,
            use_aapt2: bool = False
    ):
        working_dir_path = MemoryTempfile().gettempdir()

        super(ManipulationStatus, self).__init__(
            apk_path,
            working_dir_path,
            obfuscated_apk_path,
            ignore_libs,
            interactive,
            virus_total_api_key,
            keystore_file,
            keystore_password,
            key_alias,
            key_password,
            ignore_packages_file,
            use_aapt2
        )

        self._string_to_encrypt = set()
        self._api_to_reflect = set()
        self._android_api_to_reflect = set()
        self._n_arithmetic_branch = 0
        self._class_to_rename = set()
        self._call_to_redirect = set()
        self._urls_to_inject = set()
        self._apis_to_inject = set()

        self._orig_decoded_apk_path = None
        self._dir_list = set()

    def update_path(self, i):
        new_decoded_apk_path = self._orig_decoded_apk_path + f"_manip_{i}"
        if os.path.exists(new_decoded_apk_path):
            rmtree(new_decoded_apk_path)
            if new_decoded_apk_path in self._dir_list:
                self._dir_list.remove(new_decoded_apk_path)

        # to save space, the assets directory (if present) is linked to the
        # original decompiled application
        copytree(
            self._orig_decoded_apk_path, new_decoded_apk_path,
            ignore=lambda directory, contents: ["assets"]
            if directory == self._orig_decoded_apk_path else [])
        if os.path.isdir(os.path.join(self._orig_decoded_apk_path, "assets")):
            os.symlink(os.path.join(self._orig_decoded_apk_path, "assets"),
                       os.path.join(new_decoded_apk_path, "assets"))

        self._decoded_apk_path = new_decoded_apk_path
        self._dir_list.add(self._decoded_apk_path)

        # Path to the decoded manifest file.
        if self.is_bundle:
            self._manifest_file = os.path.join(
                self._decoded_apk_path,
                "base",
                "manifest",
                "AndroidManifest.xml",
            )
        else:
            self._manifest_file = os.path.join(
                self._decoded_apk_path, "AndroidManifest.xml"
            )

        # A list containing the paths to all the smali files obtained with
        # apktool or bundledecompiler.
        self._smali_files = [
            os.path.join(root, file_name)
            for root, dir_names, file_names in os.walk(self._decoded_apk_path)
            for file_name in file_names
            if file_name.endswith(".smali")
        ]

        if self.ignore_libs:
            # Normalize paths for the current OS ('.join(x, "")' is used to add
            # a trailing slash).
            libs_to_ignore = list(
                map(
                    lambda x: os.path.join(os.path.normpath(x), ""),
                    util.get_libs_to_ignore(),
                )
            )
            filtered_smali_files = []

            for smali_file in self._smali_files:
                # Get the path without the initial part <root>/smali/.
                relative_smali_file = os.path.join(
                    *(
                        os.path.relpath(
                            smali_file, self._decoded_apk_path
                        ).split(os.path.sep)[1:]
                    )
                )
                # Get only the smali files that are not part of known third
                # party libraries.
                if not any(
                        relative_smali_file.startswith(lib)
                        for lib in libs_to_ignore
                ):
                    filtered_smali_files.append(smali_file)

            self._smali_files = filtered_smali_files

        # Sort the list of smali files to always have the list in the same
        # order.
        self._smali_files.sort()

        # Check if multidex.
        if self.is_bundle:
            if os.path.isdir(
                    os.path.join(
                        self._decoded_apk_path, "base", "dex", "smali_classes2"
                    )
            ):
                self._is_multidex = True
        else:
            if os.path.isdir(
                    os.path.join(self._decoded_apk_path, "smali_classes2")
            ):
                self._is_multidex = True

        if self._is_multidex:
            smali_directories = ["smali"]
            for i in range(2, 15):
                smali_directories.append("smali_classes{0}".format(i))

            for smali_directory in smali_directories:
                if self.is_bundle:
                    current_directory = os.path.join(
                        self._decoded_apk_path,
                        "base",
                        "dex",
                        smali_directory,
                        "",
                    )
                else:
                    current_directory = os.path.join(
                        self._decoded_apk_path, smali_directory, ""
                    )
                if os.path.isdir(current_directory):
                    self._multidex_smali_files.append(
                        [
                            smali_file
                            for smali_file in self._smali_files
                            if smali_file.startswith(current_directory)
                        ]
                    )

        # A list containing the paths to the native libraries included in the
        # application.
        self._native_lib_files = [
            os.path.join(root, file_name)
            for root, dir_names, file_names in os.walk(
                os.path.join(self._decoded_apk_path, "lib")
            )
            for file_name in file_names
            if file_name.endswith(".so")
        ]

        # Sort the list of native libraries to always have the list in the
        # same order.
        self._native_lib_files.sort()

    def decode_apk(self, skip_resources=False, skip_code=False,
                   only_main_dex=False) -> None:

        if not self._is_decoded:
            # The input apk will be decoded with apktool or BundleDecompiler.
            apktool: Apktool_ = Apktool_()
            bundledecompiler: BundleDecompiler = BundleDecompiler()

            # <working_directory>/<apk_path>/
            self._decoded_apk_path = os.path.join(
                self.working_dir_path,
                os.path.splitext(os.path.basename(self.apk_path))[0],
            )
            self._dir_list.add(self._decoded_apk_path)
            try:
                if self.is_bundle:
                    bundledecompiler.decode(
                        self.apk_path, self._decoded_apk_path, force=False
                    )
                else:
                    apktool.decode(self.apk_path, self._decoded_apk_path,
                                   force=True, skip_resources=skip_resources,
                                   skip_code=skip_code,
                                   only_main_dex=only_main_dex)

                # Path to the decoded manifest file.
                if self.is_bundle:
                    self._manifest_file = os.path.join(
                        self._decoded_apk_path,
                        "base",
                        "manifest",
                        "AndroidManifest.xml",
                    )
                else:
                    self._manifest_file = os.path.join(
                        self._decoded_apk_path, "AndroidManifest.xml"
                    )

                # A list containing the paths to all the smali files obtained with
                # apktool or bundledecompiler.
                self._smali_files = [
                    os.path.join(root, file_name)
                    for root, dir_names, file_names in
                    os.walk(self._decoded_apk_path)
                    for file_name in file_names
                    if file_name.endswith(".smali")
                ]

                if self.ignore_libs:
                    # Normalize paths for the current OS ('.join(x, "")' is used to add
                    # a trailing slash).
                    libs_to_ignore = list(
                        map(
                            lambda x: os.path.join(os.path.normpath(x), ""),
                            util.get_libs_to_ignore(),
                        )
                    )
                    filtered_smali_files = []

                    for smali_file in self._smali_files:
                        # Get the path without the initial part <root>/smali/.
                        relative_smali_file = os.path.join(
                            *(
                                os.path.relpath(
                                    smali_file, self._decoded_apk_path
                                ).split(os.path.sep)[1:]
                            )
                        )
                        # Get only the smali files that are not part of known third
                        # party libraries.
                        if not any(
                                relative_smali_file.startswith(lib)
                                for lib in libs_to_ignore
                        ):
                            filtered_smali_files.append(smali_file)

                    self._smali_files = filtered_smali_files

                # Sort the list of smali files to always have the list in the same
                # order.
                self._smali_files.sort()

                # Check if multidex.
                if self.is_bundle:
                    if os.path.isdir(
                            os.path.join(
                                self._decoded_apk_path, "base", "dex",
                                "smali_classes2"
                            )
                    ):
                        self._is_multidex = True
                else:
                    if os.path.isdir(
                            os.path.join(self._decoded_apk_path,
                                         "smali_classes2")
                    ):
                        self._is_multidex = True

                if self._is_multidex:
                    smali_directories = ["smali"]
                    for i in range(2, 15):
                        smali_directories.append("smali_classes{0}".format(i))

                    for smali_directory in smali_directories:
                        if self.is_bundle:
                            current_directory = os.path.join(
                                self._decoded_apk_path,
                                "base",
                                "dex",
                                smali_directory,
                                "",
                            )
                        else:
                            current_directory = os.path.join(
                                self._decoded_apk_path, smali_directory, ""
                            )
                        if os.path.isdir(current_directory):
                            self._multidex_smali_files.append(
                                [
                                    smali_file
                                    for smali_file in self._smali_files
                                    if smali_file.startswith(current_directory)
                                ]
                            )

                # A list containing the paths to the native libraries included in the
                # application.
                self._native_lib_files = [
                    os.path.join(root, file_name)
                    for root, dir_names, file_names in os.walk(
                        os.path.join(self._decoded_apk_path, "lib")
                    )
                    for file_name in file_names
                    if file_name.endswith(".so")
                ]

                # Sort the list of native libraries to always have the list in the
                # same order.
                self._native_lib_files.sort()

            except Exception as e:
                self.logger.error("Error during apk decoding: {0}".format(e))
                raise
            else:
                self._is_decoded = True

        self._orig_decoded_apk_path = self._decoded_apk_path

    @property
    def string_to_encrypt(self):
        return self._string_to_encrypt

    @string_to_encrypt.setter
    def string_to_encrypt(self, value):
        self._string_to_encrypt = value

    @property
    def android_api_to_reflect(self):
        return self._android_api_to_reflect

    @android_api_to_reflect.setter
    def android_api_to_reflect(self, value):
        self._android_api_to_reflect = value

    @property
    def class_to_rename(self):
        return self._class_to_rename

    @class_to_rename.setter
    def class_to_rename(self, value):
        self._class_to_rename = value

    @property
    def urls_to_inject(self):
        return self._urls_to_inject

    @urls_to_inject.setter
    def urls_to_inject(self, value):
        self._urls_to_inject = value

    @property
    def apis_to_inject(self):
        return self._apis_to_inject

    @apis_to_inject.setter
    def apis_to_inject(self, value):
        self._apis_to_inject = value

    def clean_iter(self, i):
        decoded_apk_path = self._orig_decoded_apk_path + f"_manip_{i}"
        if os.path.exists(decoded_apk_path):
            rmtree(decoded_apk_path)

    def clean_data(self):
        for data_dir in self._dir_list:
            if os.path.exists(data_dir):
                rmtree(data_dir)

    def reset(self):
        self.class_to_rename = set()
        self.android_api_to_reflect = set()
        self.string_to_encrypt = set()
        self.urls_to_inject = set()
        self.apis_to_inject = set()
        self.obfuscators_adding_fields = 0
        self.obfuscators_adding_methods = 0
        self.decrypt_asset_smali_file_added_flag = False
        self.decrypt_string_smali_file_added_flag = False
