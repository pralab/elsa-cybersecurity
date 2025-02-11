"""
Configuration file for all the evaluation tracks.
Read before running any evaluation script and edit if needed.
"""


"""Directories where to store the APK files of Track 2 and 3 test datasets,
and the adversarial examples produced by the problem-space attack.
"""
TS_ROUND_DIR = "data/test_set_round_{}"
TS_FP_CHECK_DIR = "data/test_set_fp_check"  # Goodware-only dataset
TS_ADV_DIR = "data/test_set_adv"  # Malware-only dataset
MANIPULATED_APKS_DIR = "data/manipulated_apks"  # Generated adversarial examples


"""The number of concurrent threads/processes that will be used during the
APKs download (in this case it will be clipped to 20) and the attack.
Note that during the attack a higher number of concurrent processes
means higher memory consumption, which might cause failures."""
N_JOBS = 1


"""If True, the APKs required for Track 2 and 3 evaluation will be 
automatically downloaded. In this case, the AndroZoo API key must be passed."""
DOWNLOAD_APKS = False


AZOO_API_KEY = ""  # The personal AndroZoo API key.


"""Dataset paths: you don't need to change them if you download the dataset
files and store them in the `data` folder."""
FEATURES_TR = "data/training_set_features.zip"
FEATURES_TS_FP_CHECK = "data/test_set_fp_check_features.zip"
FEATURES_TS_ADV = "data/test_set_adv_features.zip"
FEATURES_TS_ROUND = "data/test_set_features_round_{}.zip"
TR = "data/training_set.zip"
TS_ROUND = "data/test_set_round_{}.zip"
TS_FP_CHECK = "data/test_set_fp_check.zip"
TS_ADV = "data/test_set_adv.zip"
