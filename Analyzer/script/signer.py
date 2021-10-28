# encoding: utf-8
"""
@project = collusionAttackDetector
@file = signer
@author = Jinz
@create_time = 2018/12/27

"""

import os
import subprocess

keytoolPath = 'D:/Application/ProgramData/jdk1.6.0_41/bin/jarsigner.exe'
apkSource = 'D:/paper/experiment/ICC_example/droidBench-inter-app/'
apkSign = 'D:/paper/experiment/ICC_example/droidBench-inter-app/signed/'

apkNames = []

for item in os.listdir(apkSource):
    if item.split('.')[-1] == 'apk':
        name = item.split('/')[-1]
        print(name)
        apkNames.append(name)

for name in apkNames:
    shell = [keytoolPath,'-verbose','-keystore','D:/demo.keystore','-signedjar',apkSign+name,apkSource+name,'demo.keystore']
    str = ''
    for item in shell:
        str = str+item+' '
    print(str)
    # p = subprocess.Popen([keytoolPath,'-verbose','-keystore','D:/demo.keystore','-signedjar',apkSign+name,apkSource+name,'demo.keystore'],stdout=subprocess.PIPE)
    # p.wait()
    # out = p.stdout.readlines()
    # print(out)
