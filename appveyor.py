"""AppVeyor Build
This file is used to build and distribute the accordably binary on appveyor. Take
a look at the corresponding appveyor.yml as well.
"""
import os
import subprocess
import sys
from collections import OrderedDict


class environment:
    WIN = "win"
    LINUX = "linux"
    MACOS = "macos"

    def __init__(self):
        os_mapping = {
            "Visual Studio 2019": self.WIN,
            "Previous Ubuntu1604": self.LINUX,
            "macOS": self.MACOS
        }
        self.os = os_mapping[os.getenv("APPVEYOR_BUILD_WORKER_IMAGE")]

    @property
    def python(self):
        for arch, python in self.PYTHON_BINARIES[self.os].items():
            yield arch, python

    PYTHON_BINARIES = {
        WIN: {
            64: "C:\\Python38-x64\\python.exe",
            32: "C:\\Python38\\python.exe",
        },

        # Order is important. If the 32 bit release gets built first,
        # you'll run into permission problems due to docker clobbering
        # up the current working directory.
        LINUX: OrderedDict([
            (64, "/usr/bin/python3.5"),
            (32, f"docker run -t -v {os.getcwd()}:/app 32-bit-linux python3"),
        ]),

        MACOS: {
            # On macOS the binary is built using Python 3.7 (Homebrew), because
            # the shipped Python lacks libraries PyInstaller needs.
            64: "/usr/local/bin/python3",
        }
    }

    def run(self, command):
        """Runs the given command via subprocess.check_output.
        Exits with -1 if the command wasn't successfull.
        """
        try:
            print(f"RUNNING: {command}")
            print("-" * 80)
            out = subprocess.check_output(command, shell=True)
            try:
                print(out.decode('utf-8'))
            except UnicodeEncodeError:
                print(out)
        except subprocess.CalledProcessError as e:
            print(f"ERROR calling '{command}'")
            print("-" * 20)
            print(e.output and e.output.decode('utf-8'))
            sys.exit(-1)

    def install(self):
        """
        Install required dependencies
        """
        # special case:
        # - build the 32 bit binary for linux on docker
        # - create dist/ path to circumvent permission errors
        if self.os == self.LINUX:
            self.run("docker build -t 32-bit-linux -f Dockerfilei386 .")
            self.run("sudo apt-get install -y python3-dev python3-pip")

        # special case:
        # install python via homebrew
        if self.os == self.MACOS:
            self.run("brew install python")

        for arch, python in self.python:
            self.run(f"{python} -m pip install setuptools")
            self.run(f"{python} -m pip install pyinstaller==3.5")
            self.run(f"{python} -m pip install pytest")
            self.run(f"{python} -m pip install -r requirements.txt")
            self.run(f"{python} -m pip freeze")

    def dist(self):
        """Runs Pyinstaller producing a binary for every platform arch."""
        for arch, python in self.python:

            # Build the binary
            build_path = os.path.join("dist", f"accordably-{arch}")
            self.run(f"{python} -m PyInstaller accordably.spec"
                     f" --distpath {build_path}")

            # There seems to be no way to tell pyinstaller the binary name.
            # This leads to problems with appveyors artifact collector because
            # every binary is named the same.
            #
            # Move them around so they can be picked up correctly
            #
            artifact_path = os.path.join(
                os.getcwd(),
                "dist",
                f"accordably-{self.os}-{'i686' if arch == 32 else 'x86_64'}"
            )
            binary_path = os.path.join(os.getcwd(), build_path, "accordably")
            if self.os == self.WIN:
                self.run(f"move {binary_path}.exe {artifact_path}.exe")
            else:
                self.run(f"cp {binary_path} {artifact_path}")

    def test(self):
        """
        Runs tests for every available arch on the current platform.
        """
        pass
        # for arch, python in self.python:
        #     self.run(f"{python} -m pytest")


if __name__ == "__main__":

    if len(sys.argv) <= 1 or sys.argv[1] not in ['install', 'test', 'dist']:
        print("usage: appveyor.py [install|test|dist]")
        sys.exit(-1)

    env = environment()

    # Runs the command in sys.argv[1] (install|test|dist)
    getattr(env, sys.argv[1])()
    sys.exit(0)
