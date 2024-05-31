### Track 2: Adversarial Robustness to Problem-space Attacks - Submission example

Download the training dataset and the Track 2 datasets from the [ELSA benchmarks website](https://benchmarks.elsa-ai.eu/?ch=6&com=downloads) inside the `data` directory.
Then, download the APK files from [AndroZoo](https://androzoo.uni.lu/) by querying for their SHA256 hashes (contained in the dataset CSV files).
The download can be automatically performed by the evaluation code (recommended), by providing your AndroZoo API key. 
If you prefer to manually download data, the APKs of the goodware-only test set must be placed inside the `data/test_set_fp_check` folder, while the malware-only test set must be placed in the `data/test_set_adv` folder.

If you want to use Docker, you can use the following commands (from the repository root directory):
```bash
docker build -t android android-detectors
docker run -itd --name android android
docker cp data android:/
docker cp track_2/. android:/android-detectors/
docker exec -it android pip install -r /android-detectors/attack_requirements.txt
docker exec -it android pip install -r /android-detectors/problem_space_attack/manipulation/Obfuscapk/src/requirements.txt
docker exec -it android python /android-detectors/drebin_track_2.py
docker stop android
```
The submission file and the pretrained model files can be gathered from the container:
```bash
docker cp android:/android-detectors/submissions/submission_drebin_track_2.json track_2/submissions/
docker cp android:/android-detectors/pretrained/drebin_classifier.pkl android-detectors/pretrained/
docker cp android:/android-detectors/pretrained/drebin_vectorizer.pkl android-detectors/pretrained/
```

If you don't want to use Docker, it is recommended to create a new environment, for instance if you use conda you can run (it might be required to append `android-detectors/src` directory to the python path before launching the script):
```bash
conda create -n android python=3.9
conda activate android
pip install -r android-detectors/requirements.txt
pip install -r track_2/attack_requirements.txt
pip install -r track_2/problem_space_attack/manipulation/Obfuscapk/src/requirements.txt
export PYTHONPATH="${PYTHONPATH}:android-detectors/src"
python3 track_2/drebin_track_2.py
```