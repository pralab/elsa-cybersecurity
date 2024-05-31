import os
import re
from typing import List, Set

from obfuscapk import util
from obfuscapk.obfuscators.advanced_reflection import AdvancedReflection

from ..manipulation_status import ManipulationStatus


class AttAdvancedReflection(AdvancedReflection):

    def obfuscate(self, obfuscation_info: ManipulationStatus):
        if not obfuscation_info.android_api_to_reflect:
            return

        self.logger.info('Running "{0}" obfuscator'.format(self.__class__.__name__))

        try:
            obfuscator_smali_code: str = ""

            move_result_pattern = re.compile(
                r"\s+move-result.*?\s(?P<register>[vp0-9]+)"
            )

            for smali_file in util.show_list_progress(
                obfuscation_info.get_smali_files(),
                interactive=obfuscation_info.interactive,
                description="Obfuscating dangerous APIs using reflection",
            ):
                self.logger.debug(
                    'Obfuscating dangerous APIs using reflection in file "{0}"'.format(
                        smali_file
                    )
                )

                # There is no space for further reflection instructions.
                if (
                    self.obfuscator_instructions_length
                    >= self.obfuscator_instructions_limit
                ):
                    break

                with open(smali_file, "r", encoding="utf-8") as current_file:
                    lines = current_file.readlines()

                # Line numbers where a method is declared.
                method_index: List[int] = []

                # For each method in method_index, True if there are enough registers
                # to perform some operations by using reflection, False otherwise.
                method_is_reflectable: List[bool] = []

                # The number of local registers of each method in method_index.
                method_local_count: List[int] = []

                # Find the method declarations in this smali file.
                for line_number, line in enumerate(lines):
                    method_match = util.method_pattern.match(line)
                    if method_match:
                        method_index.append(line_number)

                        param_count = self.count_needed_registers(
                            self.split_method_params(method_match.group("method_param"))
                        )

                        # Save the number of local registers of this method.
                        local_count = 16
                        local_match = util.locals_pattern.match(lines[line_number + 1])
                        if local_match:
                            local_count = int(local_match.group("local_count"))
                            method_local_count.append(local_count)
                        else:
                            # For some reason the locals declaration was not found where
                            # it should be, so assume the local registers are all used.
                            method_local_count.append(local_count)

                        # If there are enough registers available we can perform some
                        # reflection operations.
                        if param_count + local_count <= 11:
                            method_is_reflectable.append(True)
                        else:
                            method_is_reflectable.append(False)

                # Look for method invocations of dangerous APIs inside the methods
                # declared in this smali file and change normal invocations with
                # invocations through reflection.
                for method_number, index in enumerate(method_index):

                    # If there are enough registers for reflection operations, look for
                    # method invocations inside each method's body.
                    if method_is_reflectable[method_number]:
                        current_line_number = index
                        while not lines[current_line_number].startswith(".end method"):

                            # There is no space for further reflection instructions.
                            if (
                                self.obfuscator_instructions_length
                                >= self.obfuscator_instructions_limit
                            ):
                                break

                            current_line_number += 1

                            invoke_match = util.invoke_pattern.match(
                                lines[current_line_number]
                            )
                            if invoke_match:
                                method = (
                                    "{class_name}->{method_name}"
                                    "({method_param}){method_return}".format(
                                        class_name=invoke_match.group("invoke_object"),
                                        method_name=invoke_match.group("invoke_method"),
                                        method_param=invoke_match.group("invoke_param"),
                                        method_return=invoke_match.group(
                                            "invoke_return"
                                        ),
                                    )
                                )

                                # Use reflection only if this method belongs to
                                # dangerous APIs.
                                if method not in obfuscation_info.android_api_to_reflect:
                                    continue

                                if (
                                    invoke_match.group("invoke_type")
                                    == "invoke-virtual"
                                ):
                                    tmp_is_virtual = True
                                elif (
                                    invoke_match.group("invoke_type") == "invoke-static"
                                ):
                                    tmp_is_virtual = False
                                else:
                                    continue

                                tmp_register = invoke_match.group("invoke_pass")
                                tmp_class_name = invoke_match.group("invoke_object")
                                tmp_method = invoke_match.group("invoke_method")
                                tmp_param = invoke_match.group("invoke_param")
                                tmp_return_type = invoke_match.group("invoke_return")

                                # Check if the method invocation result is used in the
                                # following lines.
                                for move_result_index in range(
                                    current_line_number + 1,
                                    min(current_line_number + 10, len(lines) - 1),
                                ):
                                    if "invoke-" in lines[move_result_index]:
                                        # New method invocation, the previous method
                                        # result is not used.
                                        break

                                    move_result_match = move_result_pattern.match(
                                        lines[move_result_index]
                                    )
                                    if move_result_match:
                                        tmp_result_register = move_result_match.group(
                                            "register"
                                        )

                                        # Fix the move-result instruction after the
                                        # method invocation.
                                        new_move_result = ""
                                        if tmp_return_type in self.primitive_types:
                                            new_move_result += (
                                                "\tmove-result-object "
                                                "{result_register}\n\n"
                                                "\tcheck-cast {result_register}, "
                                                "{result_class}\n\n".format(
                                                    result_register=tmp_result_register,
                                                    result_class=self.type_dict[
                                                        tmp_return_type
                                                    ],
                                                )
                                            )

                                            new_move_result += "\tinvoke-virtual " "{{{result_register}}}, {cast}\n\n".format(
                                                result_register=tmp_result_register,
                                                cast=self.reverse_cast_dict[
                                                    tmp_return_type
                                                ],
                                            )

                                            if (
                                                tmp_return_type == "J"
                                                or tmp_return_type == "D"
                                            ):
                                                new_move_result += (
                                                    "\tmove-result-wide "
                                                    "{result_register}\n".format(
                                                        result_register=tmp_result_register
                                                    )
                                                )
                                            else:
                                                new_move_result += (
                                                    "\tmove-result "
                                                    "{result_register}\n".format(
                                                        result_register=tmp_result_register
                                                    )
                                                )

                                        else:
                                            new_move_result += (
                                                "\tmove-result-object "
                                                "{result_register}\n\n"
                                                "\tcheck-cast {result_register}, "
                                                "{return_type}\n".format(
                                                    result_register=tmp_result_register,
                                                    return_type=tmp_return_type,
                                                )
                                            )

                                        lines[move_result_index] = new_move_result

                                # Add the original method to the list of methods using
                                # reflection.
                                obfuscator_smali_code += self.add_smali_reflection_code(
                                    tmp_class_name, tmp_method, tmp_param
                                )

                                # Change the original code with code using reflection.
                                lines[
                                    current_line_number
                                ] = self.create_reflection_method(
                                    self.methods_with_reflection,
                                    method_local_count[method_number],
                                    tmp_is_virtual,
                                    tmp_register,
                                    tmp_param,
                                )

                                self.methods_with_reflection += 1

                                # Add the registers needed for performing reflection.
                                lines[index + 1] = "\t.locals {0}\n".format(
                                    method_local_count[method_number] + 4
                                )

                with open(smali_file, "w", encoding="utf-8") as current_file:
                    current_file.writelines(lines)

            # Add to the app the code needed for the reflection obfuscator. The code
            # can be put in any smali directory, since it will be moved to the correct
            # directory when rebuilding the application.
            destination_dir = os.path.dirname(obfuscation_info.get_smali_files()[0])
            destination_file = os.path.join(
                destination_dir, "AdvancedApiReflection.smali"
            )
            with open(destination_file, "w", encoding="utf-8") as api_reflection_smali:
                reflection_code = util.get_advanced_api_reflection_smali_code().replace(
                    "#!code_to_replace!#", obfuscator_smali_code
                )
                api_reflection_smali.write(reflection_code)

        except Exception as e:
            self.logger.error(
                'Error during execution of "{0}" obfuscator: {1}'.format(
                    self.__class__.__name__, e
                )
            )
            raise

        finally:
            obfuscation_info.used_obfuscators.append(self.__class__.__name__)
