# qber.py

import numpy as np


def calculate_qber(alice_key, bob_key):
    min_len = min(len(alice_key), len(bob_key))

    if min_len == 0:
        return 0

    errors = np.sum(alice_key[:min_len] != bob_key[:min_len])
    return errors / min_len
