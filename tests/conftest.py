"""Run the test suite against a throwaway database, never the real data.sqlite3."""
import atexit
import os
import shutil
import tempfile

_tmp = tempfile.mkdtemp(prefix="dkcissp-tests-")
os.environ["DKCISSP_DB"] = os.path.join(_tmp, "test.sqlite3")
atexit.register(shutil.rmtree, _tmp, ignore_errors=True)
