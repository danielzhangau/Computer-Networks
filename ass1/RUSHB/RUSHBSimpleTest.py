import sys
import subprocess
import time
import os
import random

STARTUP_TIMEOUT = 10
RUN_TIMEOUT = 15
VALID_MODES = ["SIMPLE", "NAK", "MULTI_NAK", "TIMEOUT", "MULTI_TIMEOUT", "INVALID_SEQ", "INVALID_ACK", "INVALID_FLAGS",
                    "ENCODED", "CHECKSUM", "ENCODED_CHECKSUM", "INVALID_ENCODE_VAL", "INVALID_CHECKSUM_VAL",
                    "INVALID_ENCODE_FLAG", "INVALID_CHECKSUM_FLAG"]

RUSHB_TESTSUITE_VERSION = '1.0'
'''
0.1 - initial release
0.2 - fix bug on connecting client
0.3 - fix bug on invalid argument
0.4 - reduce port number on client
0.5 - fix bugs on large port number
1.0 - official sample test suit
1.1 - fix bugs
'''

def main(argv):
    print('RUSHB_TEST_VERSION: ' + RUSHB_TESTSUITE_VERSION)

    if len(argv) < 1:
        print("Usage: python3 RUSHBSimpleTest.py mode")
        return

    if os.path.isfile("makefile") or os.path.isfile("Makefile"):
        try:
            subprocess.check_output(["make"])
        except subprocess.CalledProcessError:
            print("Error occured when calling make.")
            return

    client_port = random.randint(11111,65534)
    print("Selected client port is {}.".format(client_port))

    mode = "SIMPLE"
    if len(argv) > 1 and argv[1] in VALID_MODES:
        mode = argv[1]
    else:
        print("Invalid mode, please check again. Now testing [SIMPLE] mode.")

    if os.path.isfile("RUSHBSvr.py"):
        call = ["python3", "RUSHBSvr.py"]
    elif os.path.isfile("RUSHBSvr.class"):
        call = ["java", "RUSHBSvr"]
    elif os.path.isfile("RUSHBSvr"):
        call = ["./RUSHBSvr"]
    else:
        print("No valid file found to call.")
        return

    serv_proc = subprocess.Popen(call, stdout=subprocess.PIPE)
    try:
        out = serv_proc.stdout.readline().decode("UTF-8")
        serv_port = int(out.partition("\n")[0].strip())
        print("Found server on port " + str(serv_port) + ".\nRunning the client...")
    except ValueError:
        print("Server port is invalid.")
        serv_proc.kill()
        return

    while True:
        try:
            cli_proc = subprocess.Popen(["python3", "RUSHBSimpleClient.py", str(client_port), str(serv_port), "-m", mode, "-v", "9", "-o", mode+"_output.txt"])
            break
        except:
            client_port = random.randint(11111, 65534)
            print("Socket error found, change the client port to {}.".format(client_port))

    try:
        cli_proc.wait(timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired:
        if mode.upper() == "INVALID_CHECKSUM_VAL":
            with open(mode + "_output.txt", "w") as f:
                f.close()
        else:
            print("\nTimeout exceeded during connection. Please use Wireshark to see what is missing.")
            cli_proc.kill()
            return

    if serv_proc.poll() is None:
        serv_proc.kill()

    with open(mode+"_output.txt", "r") as f, open(os.path.join("test_files", mode + "_output.txt"), "r") as g:
        output = f.read()
        expected = g.read()
        if output == expected:
            print("\n[{}] is tested successfully. Output is as expected.".format(mode))
        else:
            print("\nDifferences in output detected.")
            print("Compare differences using diff {}_output.txt {}_output.txt".format(mode, os.path.join("test_files", mode)))

if __name__ == "__main__":
    main(sys.argv)
