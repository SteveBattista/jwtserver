#!/bin/sh
/home/complier/projects/jwtserver/.venv/bin/python -c "import os, hashlib; print(hashlib.sha512(os.urandom(64)).hexdigest())"