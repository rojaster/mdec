import os
import subprocess
import tempfile

from mdecbase import Service


class GhidraService(Service):
    """
    Ghidra as a service
    """
    def decompile(self, path: str) -> str:
        """
        Decompile all the functions in the binary located at `path`.
        """
        return self.process(path, '/opt/ghidra/dump.py')

    def lifting(self, path: str) -> str:
        """
        Lift to PCODE all functions in the binary located at `path`
        """
        return self.process(path, '/opt/ghidra/lift.py')

    def process(self, path: str, script: str) -> str:
        """
        Process given binary
        """
        original_cwd = os.getcwd()
        code = ''
        try:
            os.chdir(os.path.dirname(path))
            subprocess.run(['/opt/ghidra/support/analyzeHeadless', '.', 'temp_project', '-import', os.path.basename(path), '-postScript', script])
            code = open('out.c').read()
        finally:
            os.chdir(original_cwd)
        return code

    def version(self) -> str:
        original_cwd = os.getcwd()
        version = ''
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.chdir(tmp)
                subprocess.run(['/opt/ghidra/support/pythonRun', '/opt/ghidra/version.py'])
                version = open('version.txt').read()
        finally:
            os.chdir(original_cwd)
        return version
