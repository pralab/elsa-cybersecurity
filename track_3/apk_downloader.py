import os
import hashlib
import logging
import requests
import sys
from multiprocessing import Pool


ANDROZOO_BASE_URL = ("https://androzoo.uni.lu/api/download?"
                     "apikey={0}&sha256={01}")


def _check_hash(file_path, sha256):
    """
    Compute the SHA256 hash on a given file and check if it matches the
    target one.

    Parameters
    ----------
    file_path : str
        Path of the file to check.
    sha256 : str
        Target SHA256 hash.

    Returns
    -------
    bool
        True if the two hashes match, False otherwise.
    """
    with open(file_path, mode="rb") as f:
        bytes = f.read()
        sha256_hash = hashlib.sha256(bytes).hexdigest().upper()
    return sha256.upper() == sha256_hash


class APKDownloader:
    """
    Class for downloading APK files from AndroZoo, given their SHA256 hash.
    An APK key is required and can be requested from AndroZoo maintainers.

    Part of this code is taken from:
    https://github.com/ArtemKushnerov/az/blob/master/modules/services/dataset_downloader.py
    """

    def __init__(self, androzoo_api_key, out_dir, logging_level=logging.INFO):
        """

        Parameters
        ----------
        androzoo_api_key : str
            The AndroZoo API key.
        out_dir : str
            The directory where the downloaded APK files will be saved.
        logging_level : int
            Set the verbosity of the logger.
        """
        self.androzoo_api_key = androzoo_api_key
        self.out_dir = out_dir
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging_level)

    def download_apks(self, apks_sha256, n_jobs=1):
        """Download a list of APK files from AndroZoo, given their SHA256 hash.

        Parameters
        ----------
        apks_sha256 : list of str
            List containing the SHA256 hashes of the APK files to download.
        n_jobs : int
            The number of concurrent threads used for downloading the APK
            files. It must be between 1 and 20. Default is 1.
        """
        if n_jobs < 1 or n_jobs > 20:
            raise ValueError("`n_jobs` must be between 1 and 20")

        self.logger.info(f"Starting download of {len(apks_sha256)} APKs "
                         f"with {n_jobs} concurrent threads")
        with Pool(n_jobs) as pool:
            pool.map(self.download_apk, apks_sha256)

    def download_apk(self, apk_sha256):
        """Download a single APK file from AndroZoo, given its SHA256 hash.

        Parameters
        ----------
        apk_sha256 : str
            The SHA256 hash of the APK file to download.
        """
        apk = apk_sha256.upper()
        apk_save_path = os.path.join(self.out_dir, f"{apk}.apk")
        try:
            if os.path.exists(apk_save_path):
                # apk already downloaded
                if _check_hash(apk_save_path, apk):
                    self.logger.debug(f"{apk}.apk already downloaded")
                    return
                else:
                    self.logger.debug(
                        f"{apk}.apk already downloaded but the file is "
                        f"corrupted, downloading again")
                    os.remove(apk_save_path)
            self.logger.debug(f"Downloading {apk}.apk")
            apk_url = ANDROZOO_BASE_URL.format(self.androzoo_api_key, apk)
            response = requests.get(apk_url)
            code = response.status_code
            if code == 200:
                with open(apk_save_path, "wb") as out_file:
                    out_file.write(response.content)
                assert _check_hash(apk_save_path, apk)
            else:
                self.logger.debug(f"HTTP code for {apk}.apk is {code}")
        except:
            self.logger.error(
                f"Unexpected error while downloading {apk}.apk: "
                f"{sys.exc_info()[1]}")
