from obfuscapk import obfuscator_category
from ..manipulation_status import ManipulationStatus
import logging
from ..util import generate_random_name
from obfuscapk import util


class StringInjection(obfuscator_category.ICodeObfuscator):

    def __init__(self):

        self.logger = logging.getLogger(
            "{0}.{1}".format(__name__, self.__class__.__name__)
        )
        super().__init__()
    
    @staticmethod
    def string_injection(urls):
        """
        Generate the instructions to inject

        Parameters
        ----------
        urls : list
            list of strings to inject

        Returns
        -------
        string
            instructions to inject in the smali
        """
        
        string_inj = ""
        
        for i, s in enumerate(urls):
            string_inj += "\tconst-string v{0}, \"{1}\"\n".format(i, s)
        return string_inj
    
    def add_function(self, smali_file, strings):
        """
        Add the function to the smali file

        Parameters
        ----------
        smali_file : string
            smali file path to modify
        strings : list
            list of strings to inject

        Returns
        -------
        bool
            True if the function with the injected strings is added. False, otherwise.
        """

        # random name generation for the function
        function_name = generate_random_name()
        # string injection definition
        string_inj = self.string_injection(strings)
        # method definition
        function_definition = (
            ".method public static {0}()V\n"
            "\t.registers {1}\n"
            "\t.line 1\n"
            "\t.prologue\n"
            "{2}\n"
            "\treturn-void\n"
            ".end method\n"
        ).format(function_name, len(strings), string_inj)

        flag = False
        with util.inplace_edit_file(smali_file) as (input_file, output_file):
            # inserting the static method inside the smali file after # direct methods comment
            for line in input_file:
                if "# direct methods" in line:
                    output_file.write(line)
                    output_file.write(function_definition)
                    flag = True
                else:
                    output_file.write(line)

        return flag

    def treat_dex(self, smali_files, max_methods_to_add, interactive):
        """
        Function to control the number of methods to add to the dex file

        Parameters
        ----------
        smali_files : list
            list of smali file to modify
        max_methods_to_add : int
            max number of methods to add to the dex
        interactive : bool
            default is False
        """
        strings = list(self.obfuscation_status.urls_to_inject)
        strings_to_inject = [strings[i:i + 15] for i in
                             range(0, len(strings), 15)]
        added_methods = 0
        for smali_file in util.show_list_progress(
            smali_files, interactive=interactive,
            description="Inserting string injection function in smali files"):
            if added_methods >= len(strings_to_inject):
                break
            if added_methods < max_methods_to_add:
                if (self.add_function(smali_file,
                                      strings_to_inject[added_methods])):
                    added_methods += 1
                else:
                    continue
            else:
                return False
        return True

    def obfuscate(self, obfuscation_info: ManipulationStatus):
        if not obfuscation_info.urls_to_inject:
            return

        self.logger.info('Running "{0}" obfuscator'.format(
            self.__class__.__name__))
        self.obfuscation_status = obfuscation_info
        
        try:
            # there is a method call limit for dex files
            max_methods_to_add = (obfuscation_info.
                                  get_remaining_methods_per_obfuscator())

            if obfuscation_info.is_multidex():
                for index, dex_smali_files in enumerate(util.show_list_progress(
                        obfuscation_info.get_multidex_smali_files(),
                        interactive=obfuscation_info.interactive,
                        unit="dex",
                        description="Processing multidex")):
                    max_methods_to_add = (
                        obfuscation_info.get_remaining_methods_per_obfuscator()
                        [index])
                    self.treat_dex(dex_smali_files, max_methods_to_add,
                                   obfuscation_info.interactive)
            else:
                self.treat_dex(
                    obfuscation_info.get_smali_files(),
                    max_methods_to_add, obfuscation_info.interactive)
        except Exception as e:
            self.logger.error(
                'Error during execution of "{0}" obfuscator: {1}'.format(
                    self.__class__.__name__, e
                )
            )
            raise

        finally:
            obfuscation_info.used_obfuscators.append(self.__class__.__name__)
