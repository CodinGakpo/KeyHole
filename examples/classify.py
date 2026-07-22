"""Honest classifier: reads the private dataset, returns ONE bounded label.

The whole dataset is in front of this code, but the only thing it is allowed to
emit is a value matching the declared enum schema — so at most ~1.58 bits leave.
"""
import os
import json

rows = open("customers.csv").read().splitlines()[1:]  # drop header
high_value = sum(1 for r in rows if float(r.split(",")[3]) > 10_000)

label = "spam" if high_value >= 2 else "ham"
json.dump(label, open(os.environ["MARK1_OUTPUT"], "w"))
