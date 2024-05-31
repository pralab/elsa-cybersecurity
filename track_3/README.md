### Track 3: Temporal Robustness to Data Drift - Submission example

Download the training dataset and the Track 3 datasets from the [ELSA benchmarks website](https://benchmarks.elsa-ai.eu/?ch=6&com=downloads) inside the `data` directory.
You can also find there the pre-extracted DREBIN features. 
If you don't want to use them, you can directly download the APK files from [AndroZoo](https://androzoo.uni.lu/) by querying for their SHA256 hashes (contained in the dataset CSV files).

If you want to use Docker, you can use the following commands (from the repository root directory):
```bash
docker build -t android android-detectors
docker run -itd --name android android
docker cp data android:/
docker cp track_3/. android:/android-detectors/
docker exec -it android python /android-detectors/drebin_track_3.py
docker stop android
```
The submission file and the pretrained model files can be gathered from the container:
```bash
docker cp android:/android-detectors/submissions/submission_drebin_track_3.json track_3/submissions/
docker cp android:/android-detectors/pretrained/drebin_classifier.pkl android-detectors/pretrained/
docker cp android:/android-detectors/pretrained/drebin_vectorizer.pkl android-detectors/pretrained/
```

If you don't want to use Docker, it is recommended to create a new environment, for instance if you use conda you can run (it might be required to append `android-detectors/src` directory to the python path before launching the script):
```bash
conda create -n android python=3.9
conda activate android
pip install -r android-detectors/requirements.txt
export PYTHONPATH="${PYTHONPATH}:android-detectors/src"
python3 track_3/drebin_track_3.py
```