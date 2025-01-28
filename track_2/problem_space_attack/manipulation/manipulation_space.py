import numpy as np


class Feature:
    def __init__(self, inject, obfuscate):
        self.inject = inject
        self.obfuscate = obfuscate


FEATURES = {
    "activities": Feature(False, True),
    "services": Feature(False, True),
    "providers": Feature(False, True),
    "receivers": Feature(False, True),
    "api_calls": Feature(True, True),
    "suspicious_calls": Feature(False, True),
    "urls": Feature(True, True)
}


class Manipulations:
    def __init__(self, inject, obfuscate):
        self._inject = inject
        self._obfuscate = obfuscate

    @property
    def inject(self):
        return self._inject

    @property
    def obfuscate(self):
        return self._obfuscate

    def __len__(self):
        return len(self.inject) + len(self.obfuscate)

    def __bool__(self):
        return self.__len__() > 0

    def get_idxs(self):
        inject_idx = [i for i, _ in enumerate(self.inject)]
        obfuscate_idx = [i + len(self.inject) for i, _ in
                         enumerate(self.obfuscate)]
        return np.array(inject_idx + obfuscate_idx)

    def get_manipulations_from_vector(self, manipulation_vector):
        inject_idx = manipulation_vector[
            manipulation_vector < len(self.inject)]
        obfuscate_idx = manipulation_vector[
            manipulation_vector >= len(self.inject)] - len(self.inject)
        return Manipulations([self.inject[i] for i in inject_idx],
                             [self.obfuscate[i] for i in obfuscate_idx])


class ManipulationSpace(Manipulations):

    def __init__(self, valid_injections, malware_features):
        inject = [v for v in valid_injections if v not in malware_features]
        obfuscate = self.get_valid_obfuscations(
            [f for f in malware_features if f not in inject])
        super(ManipulationSpace, self).__init__(inject, obfuscate)

    @staticmethod
    def get_valid_obfuscations(malware_features):
        return [feat for feat in malware_features
                if FEATURES[feat.split("::")[0]].obfuscate]

    @staticmethod
    def get_valid_injections(feature_list):
        valid_injections = [
            feat for features in feature_list for feat in features
            if FEATURES[feat.split("::")[0]].inject
            and not ((feat.startswith("api_calls::") or
                      feat.startswith("suspicious_calls::")) and not
                     (feat.endswith("()V") or feat.endswith("()Z") or
                      feat.endswith("()I")))
        ]
        return valid_injections

    def get_all_manipulations(self):
        return Manipulations(self.inject, self.obfuscate)

    def get_all_injections(self):
        return Manipulations(self.inject, [])

    def get_all_obfuscations(self):
        return Manipulations([], self.obfuscate)

    def get_vector_from_manipulations(self, manipulations):
        inject_idx = [i for i, _ in enumerate(manipulations.inject)]
        obfuscate_idx = [i + len(self.inject) for i, _ in
                         enumerate(manipulations.obfuscate)]
        return np.array(inject_idx + obfuscate_idx)

    def set_error_free_manipulations(self, error_free_manipulations):
        self._inject = [i for i in error_free_manipulations.inject]
        self._obfuscate = [o for o in error_free_manipulations.obfuscate]
