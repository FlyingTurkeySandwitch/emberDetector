import argparse, ember, lightgbm as lgb, os

def main(data_dir: str):
    print(f"[1/2] Vectorizing features in {data_dir} …")
    ember.create_vectorized_features(data_dir)  # writes X_*.dat and y_*.dat

    print(f"[2/2] Training LightGBM …")
    model = ember.train_model(data_dir)         # returns a Booster
    out = os.path.join(data_dir, "ember_model_2018.txt")
    model.save_model(out)
    print("Done ->", out)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("data_dir", help="Path to ember2018 or ember2017 directory")
    args = ap.parse_args()
    main(args.data_dir)
