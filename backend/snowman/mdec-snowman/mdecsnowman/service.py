import os
import subprocess

from mdecbase import Service


class SnowmanService(Service):
    """
    Snowman decompiler as a service
    """

    def lifting(self, path: str) -> str:
        """
        Lifting all functions to IR level
        """
        return self.process(path, 'ir')

    def decompile(self, path: str) -> str:
        """
        Decompile all the functions in the binary located at `path`.
        """
        return self.process(path, 'cxx')

    def process(self, path: str, suffix: str) -> str:
        result_file = os.path.basename(path) + '.' + suffix
        subprocess.run(['/opt/snowman/bin/nocode',
                        f'--print-{suffix}={result_file}',
                        path], check=True)
        return open(result_file).read()

    def version(self) -> str:
        # There is no --version, but there is version information in --help (commit hash only?)
        proc = subprocess.Popen(
            ['/opt/snowman/bin/nocode', '--help'], stdout=subprocess.PIPE)
        (stdout, stderr) = proc.communicate()
        lines = stdout.decode('utf-8').split('\n')
        version_lines = [l for l in lines if l.startswith("Version: ")]
        assert len(version_lines) > 0
        version_line = version_lines[0].strip()
        return version_line.split(':')[1].strip()
