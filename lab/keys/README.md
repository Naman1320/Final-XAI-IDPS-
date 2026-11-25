# Model signing key (public half)

The sensor image copies this folder to `/opt/idps/keys/`. When `model-signing.pub` is here,
`live.sh` sets `IDPS_MODEL_PUBLIC_KEY` and the sensor refuses any model without a valid
signature from the matching private key (`idps/detect/signing.py`).

Make a key pair once, with the private key **outside** the repository (it never goes on a
sensor; `.dockerignore` keeps `*.key` out of images anyway):

    python -m idps.detect keygen --out ~/.idps-lab/model-signing
    cp ~/.idps-lab/model-signing.pub lab/keys/

Sign each model you put on the sensor, then rebuild the sensor image:

    python -m idps.detect sign models/week_xgboost_fb1.joblib --key ~/.idps-lab/model-signing.key

The `.pub` file is git-ignored: it belongs to your own key pair.
