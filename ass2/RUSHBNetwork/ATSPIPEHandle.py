import subprocess
import multiprocessing
import sys


def main():
    proc = subprocess.Popen(["python3", "AsynchronousTCPServerListening.py"], stdout=subprocess.PIPE)
    print("RUNNING THE SERVER", flush=True)

    # outs = proc.communicate()[0]
    # code = proc.returncode
    # print(outs)

    while True:
        next_line = proc.stdout.readline()
        if next_line == '' and proc.poll() is not None:
            break
        sys.stdout.write(next_line.decode())
        sys.stdout.flush()


if __name__ == "__main__":
    main()
