import os
import subprocess

from mdecbase import Service


class RetdecService(Service):
    """
    RetDec decompiler as a service
    """
    def process(self, path: str, suffix: str) -> str:
        """
        Process given binary and dump .c, .ll files
        Use '.c' as output, because it dumps '.ll' also
        """
        subprocess.run(['/opt/retdec/bin/retdec-decompiler', '-o', path + '.c', path])
        return open(path + suffix).read()

    def lifting(self, path: str) -> str:
        """
        Read .ll dumped IR after processing given file.
        """
        return self.process(path, '.ll')

    def decompile(self, path: str) -> str:
        """
        Decompile all the functions in the binary located at `path`.
        """
        return self.process(path, '.c')

    def version(self) -> str:
        output = subprocess.check_output(['/opt/retdec/bin/retdec', '--version']).decode('utf-8')
        lines = output.split('\n')
        version_lines = [l for l in lines if l.startswith('RetDec version')]
        assert len(version_lines) > 0
        # 'RetDec version :  v4.0-414-gc990727e'
        version_line = version_lines[0].strip()
        assert version_line.startswith('RetDec version :  ')
        return version_line.split(':')[1].strip()
