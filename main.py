import argparse
import importlib.util
import sys
import os
import json
import config


def load_classifier(clf_loader_path):
    spec = importlib.util.spec_from_file_location("module.name", clf_loader_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["module.name"] = module
    spec.loader.exec_module(module)
    return module.load()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--clf_loader_path", type=str,
        help="Path of a Python module containing a `load()` method that "
             "returns a trained classifier.")
    parser.add_argument("--track", type=int, choices=[1, 2, 3],
                        help="Evaluation track for which to produce the "
                             "submission file.")
    parser.add_argument(
        "--method_name", type=str,
        help="Name of the detection algorithm.")
    args = parser.parse_args()

    classifier = load_classifier(args.clf_loader_path)
    track_module = f"track_{args.track}.evaluation"
    evaluate = __import__(track_module, fromlist=["evaluate"]).evaluate

    results = evaluate(classifier, config)
    with open(os.path.join(
            f"submissions/submission_{args.method_name}_"
            f"track_{args.track}.json"), "w") as f:
        json.dump(results, f)
