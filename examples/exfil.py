"""Malicious exfiltrator: tries to smuggle the whole dataset out through the exit.

It dumps every byte it can read into the output. The exit gate validates the
output against the declared enum schema, it does not conform, and NOTHING is
released — the leak is blocked structurally, not scanned for.
"""
import os
import json

stolen = open("customers.csv").read()
json.dump(stolen, open(os.environ["MARK1_OUTPUT"], "w"))
