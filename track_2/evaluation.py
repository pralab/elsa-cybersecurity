from problem_space_attack import ProblemSpaceAttack
from models.base import BaseModel
from models.utils import *
import os
import logging
from apk_downloader import APKDownloader
import pandas as pd
from zipfile import ZipFile, ZIP_DEFLATED


def _download_apks(androzoo_api_key, ds_file, out_dir, n_jobs=1):
    n_jobs = min(n_jobs, 20)
    downloader = APKDownloader(androzoo_api_key, out_dir)
    with ZipFile(ds_file, "r", ZIP_DEFLATED) as z:
        ds_csv = pd.concat(
            [pd.read_csv(z.open(f))[["sha256"]]
             for f in z.namelist()], ignore_index=True)
        apks_sha256 = ds_csv.sha256.values.tolist()
    downloader.download_apks(apks_sha256, n_jobs=n_jobs)


def evaluate(classifier, download_apks=False, androzoo_api_key=None, n_jobs=1):
    """Evaluate the given classifier with the problem-space attack, after
    downloading the required APK files from AndroZoo if needed.

    Parameters
    ----------
    classifier : BaseModel
        The classifier to evaluate. Must extend the `BaseModel` interface,
        by implementing the `classify` method.
    download_apks : bool
        If True, the APKs required for the evaluation will be automatically
        downloaded. In this case, the AndroZoo API key must be passed.
    androzoo_api_key : str
        The personal AndroZoo API key.
    n_jobs : int
        The number of concurrent threads/processes that will be used during the
        APKs download (in this case it will be clipped to 20) and the attack.
        Note that during the attack a higher number of concurrent processes
        means higher memory consumption, which might cause failures.

    Returns
    -------
    dict
        A dictionary automatically filled with the evaluation results,
        that can be saved in JSON format to be uploaded.
    """
    base_path = os.path.join(os.path.dirname(__file__))
    ts_fp_check_dir = os.path.join(base_path, "../data/test_set_fp_check")
    ts_adv_dir = os.path.join(base_path, "../data/test_set_adv")
    manipulated_apks_dir = os.path.join(base_path, "../data/manipulated_apks")

    if download_apks:
        ts_fp_check_ds = os.path.join(
            base_path, "../data/test_set_fp_check.zip")
        _download_apks(
            androzoo_api_key, ts_fp_check_ds, ts_fp_check_dir, n_jobs)
        ts_adv_ds = os.path.join(base_path, "../data/test_set_adv.zip")
        _download_apks(
            androzoo_api_key, ts_adv_ds, ts_adv_dir, n_jobs)

    results = []

    ts_fp_check = sorted(
        [os.path.join(ts_fp_check_dir, apk) for apk in
         os.listdir(ts_fp_check_dir)], key=os.path.getctime)
    y_pred, scores = classifier.classify(ts_fp_check)

    results.append({
        sha256: [int(y), float(s)] for sha256, y, s in zip(
            [apk.split(".")[0] for apk in ts_fp_check], y_pred, scores)})

    ts_adv = sorted([os.path.join(ts_adv_dir, apk) for apk in
                     os.listdir(ts_adv_dir)], key=os.path.getctime)
    y_pred, scores = classifier.classify(ts_adv)

    results.append({
        sha256: [int(y), float(s)] for sha256, y, s in zip(
            [apk.split(".")[0] for apk in ts_adv], y_pred, scores)})

    attack = ProblemSpaceAttack(classifier=classifier,
                                manipulated_apks_dir=manipulated_apks_dir,
                                logging_level=logging.INFO)

    adv_results = attack.run(ts_adv, ts_fp_check, n_iterations=5,
                             n_features=100, n_jobs=n_jobs, n_candidates=20)

    results.append({sha256: [int(adv_result[0]), float(adv_result[1])]
                    for sha256, adv_result in zip(
            [apk.split(".")[0] for apk in ts_adv], adv_results)})

    return results
