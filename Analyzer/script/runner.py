import subprocess
import os
from subprocess import call, PIPE, Popen
import time

scriptPath = '/home/jinxking/Android/mybox/script/'
apkPath = '../apk/'
commands = [
['python','detect.py',apkPath+'DeviceId_Broadcast1.apk ',apkPath+'Collector.apk'],
['python','detect.py',apkPath+'DeviceId_OrderedIntent1.apk ',apkPath+'Collector.apk'],
['python','detect.py',apkPath+'DeviceId_Service1.apk ',apkPath+'Collector.apk'],
['python','detect.py',apkPath+'Location1.apk ',apkPath+'Collector.apk'],
['python','detect.py',apkPath+'Location_Broadcast1.apk ',apkPath+'Collector.apk'],
['python','detect.py',apkPath+'SendSMS.apk ',apkPath,'Echoer.apk'],
['python','detect.py',apkPath+'StartActivityForResult1.apk ',apkPath+'Echoer.apk'],
]

os.chdir(scriptPath)
for cm in commands:
	print cm
	call(cm, stderr=PIPE)