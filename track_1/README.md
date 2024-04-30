### Track 1 - Adversarial Robustness to Feature-space Attacks - Submission example

Download all the datasets and pre-computed features from the [ELSA benchmarks website](https://benchmarks.elsa-ai.eu/?ch=6&com=downloads) inside the `data` directory.

If you want to use Docker, you can use the following commands (from the repository root directory):
```bash
docker build -t android android-detectors
docker run -itd --name android android
docker cp data android:/
docker cp track_1/. android:/android-detectors/
docker exec -it android pip install -r /android-detectors/attack_requirements.txt
docker exec -it android python /android-detectors/drebin_track_1.py
docker stop android
```
The submission file and the pretrained model files can be gathered from the container:
```bash
docker cp android:/android-detectors/submissions/submission_drebin_track_1.json track_1/submissions/
docker cp android:/android-detectors/pretrained/drebin_classifier.pkl android-detectors/pretrained/
docker cp android:/android-detectors/pretrained/drebin_vectorizer.pkl android-detectors/pretrained/
```

If you don't want to use Docker, it is recommended to create a new environment, for instance if you use conda you can run (it might be required to append `android-detectors/src` directory to the python path before launching the script):
```bash
conda create -n android python=3.9
conda activate android
pip install -r android-detectors/requirements.txt
pip install -r track_1/attack_requirements.txt
export PYTHONPATH="${PYTHONPATH}:android-detectors/src"
python3 track_1/drebin_track_1.py
```