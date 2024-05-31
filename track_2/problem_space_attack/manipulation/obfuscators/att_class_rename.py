import xml.etree.cElementTree as Xml
import os
from typing import List, Set

from obfuscapk import util
from obfuscapk.obfuscators.class_rename import ClassRename
from ..manipulation_status import ManipulationStatus


class AttClassRename(ClassRename):

    def obfuscate(self, obfuscation_info: ManipulationStatus):
        if not obfuscation_info.class_to_rename:
            return

        self.obfuscation_status = obfuscation_info

        self.logger.info(
            'Running "{0}" obfuscator'.format(self.__class__.__name__))

        try:
            Xml.register_namespace(
                "android", "http://schemas.android.com/apk/res/android"
            )

            xml_parser = Xml.XMLParser(encoding="utf-8")
            manifest_tree = Xml.parse(
                obfuscation_info.get_manifest_file(), parser=xml_parser
            )
            manifest_root = manifest_tree.getroot()

            self.package_name = manifest_root.get("package")
            if not self.package_name:
                raise Exception(
                    "Unable to extract package name from application manifest"
                )

            # Get a mapping between class name and smali file path.
            for smali_file in util.show_list_progress(
                    obfuscation_info.get_smali_files(),
                    interactive=obfuscation_info.interactive,
                    description="Class name to smali file mapping",
            ):
                with open(smali_file, "r", encoding="utf-8") as current_file:
                    class_name = None
                    for line in current_file:
                        if not class_name:
                            # Every smali file contains a class.
                            class_match = util.class_pattern.match(line)
                            if class_match:
                                self.class_name_to_smali_file[
                                    class_match.group("class_name")
                                ] = smali_file
                                break

            self.transform_package_name(manifest_root)

            # Write the changes into the manifest file.
            manifest_tree.write(obfuscation_info.get_manifest_file(),
                                encoding="utf-8")

            xml_files: Set[str] = set(
                os.path.join(root, file_name)
                for root, dir_names, file_names in os.walk(
                    obfuscation_info.get_resource_directory()
                )
                for file_name in file_names
                if file_name.endswith(".xml")
                and (
                        "layout" in root or "xml" in root or
                        ("values" in root and file_name != "strings.xml")
                )  # Only res/layout-*/ and res/xml-*/ folders.
                # FIXME: added "values" folder, it might have side effects
            )
            xml_files.add(obfuscation_info.get_manifest_file())

            # TODO: use the following code to rename only the classes declared in
            #  application's package.

            # package_smali_files: Set[str] = set(
            #     smali_file
            #     for class_name, smali_file in self.class_name_to_smali_file.items()
            #     if class_name[1:].startswith(self.package_name.replace(".", "/"))
            # )
            #
            # # Rename the classes declared in the application's package.
            # class_rename_transformations = self.rename_class_declarations(
            #     list(package_smali_files), obfuscation_info.interactive
            # )

            # Get user defined ignore package list.
            self.ignore_package_names = obfuscation_info.get_ignore_package_names()

            # Rename all classes declared in smali files.
            class_rename_transformations = self.rename_class_declarations(
                obfuscation_info.get_smali_files(),
                obfuscation_info.interactive
            )

            # Update renamed classes through all the smali files.
            self.rename_class_usages_in_smali(
                obfuscation_info.get_smali_files(),
                class_rename_transformations,
                obfuscation_info.interactive,
            )

            # Update renamed classes through all the xml files.
            self.rename_class_usages_in_xml(
                list(xml_files),
                class_rename_transformations,
                obfuscation_info.interactive,
            )

        except Exception as e:
            self.logger.error(
                'Error during execution of "{0}" obfuscator: {1}'.format(
                    self.__class__.__name__, e
                )
            )
            raise

        finally:
            obfuscation_info.used_obfuscators.append(self.__class__.__name__)

    def should_encrypt(self, class_name):
        return class_name in self.obfuscation_status.class_to_rename

    def rename_class_declarations(
        self, smali_files: List[str], interactive: bool = False
    ) -> dict:
        renamed_classes = {}

        # Search for class declarations that can be renamed.
        for smali_file in util.show_list_progress(
            smali_files,
            interactive=interactive,
            description="Renaming class declarations",
        ):
            annotation_flag = False
            with util.inplace_edit_file(smali_file) as (in_file, out_file):

                skip_remaining_lines = False
                class_name = None
                r_class = False
                skip_subclass = True

                for line in in_file:

                    if skip_remaining_lines:
                        out_file.write(line)
                        continue

                    if not class_name:
                        class_match = util.class_pattern.match(line)
                        if class_match:
                            class_name = class_match.group("class_name")

                            if self.should_encrypt(class_name):

                                skip_subclass = False

                                ignore_class = class_name.startswith(
                                    tuple(self.ignore_package_names)
                                )

                                # Split class name to its components and encrypt them.
                                class_tokens = self.split_class_pattern.split(
                                    class_name[1:-1]
                                )

                                encrypted_class_name = "L"
                                separator_index = 1
                                for token in class_tokens:
                                    separator_index += len(token)
                                    if token == "R":
                                        r_class = True
                                    if token.isdigit():
                                        encrypted_class_name += (
                                            token + class_name[separator_index]
                                        )
                                    elif not r_class and not ignore_class:
                                        encrypted_class_name += (
                                            self.encrypt_identifier(token)
                                            + class_name[separator_index]
                                        )
                                    else:
                                        encrypted_class_name += (
                                            token + class_name[separator_index]
                                        )
                                    separator_index += 1

                                out_file.write(
                                    line.replace(class_name,
                                                 encrypted_class_name)
                                )

                                renamed_classes[
                                    class_name] = encrypted_class_name
                                continue

                            else:
                                skip_subclass = True

                    if (
                        line.strip()
                        == ".annotation system Ldalvik/annotation/InnerClass;"
                    ):
                        annotation_flag = True
                        out_file.write(line)
                        continue

                    if annotation_flag and 'name = "' in line:
                        # Subclasses have to be renamed as well.
                        subclass_match = self.subclass_name_pattern.match(line)
                        if subclass_match and not r_class \
                                and not skip_subclass:
                            subclass_name = subclass_match.group(
                                "subclass_name")

                            out_file.write(
                                line.replace(
                                    subclass_name,
                                    self.encrypt_identifier(subclass_name),
                                )
                            )
                        else:
                            out_file.write(line)
                        continue

                    if line.strip() == ".end annotation":
                        annotation_flag = False
                        out_file.write(line)
                        continue

                    # Method declaration reached, no more class definitions in
                    # this file.
                    if line.startswith(".method "):
                        skip_remaining_lines = True
                        out_file.write(line)
                    else:
                        out_file.write(line)

        return renamed_classes
