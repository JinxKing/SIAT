# encoding: utf-8
"""
@project = collusionAttackDetector
@file = detect
@author = Jinz
@create_time = 2018/12/19

"""
import applicationInfo
import sys
import os
from subprocess import call, PIPE, Popen
import subprocess
import logAnalysis
from datetime import datetime

names= []
apps = []
dataContactPerm = {
    'deviceid':'android.permission.READ_PHONE_STATE',
    'contacts':'android.permission.READ_CONTACTS',
    'location_gps':'android.permission.ACCESS_FINE_LOCATION',
    'location_net':'android.permission.ACCESS_FINE_LOCATION',
    'phone number':'android.permission.READ_PHONE_STATE',
    'imei':'android.permission.READ_PHONE_STATE',
    'sms':'android.permission.READ_SMS',
    'browse-mark':'',
    'simserialnumber':'android.permission.READ_PHONE_STATE',
    'subscriberid':'android.permission.READ_PHONE_STATE',
    'network state':'android.permission.ACCESS_NETWORK_STATE',
    'network subtype':'android.permission.ACCESS_NETWORK_STATE',
    'network type':'android.permission.ACCESS_NETWORK_STATE',
    'writer':'android.permission.WRITE_EXTERNAL_STORAGE',
    'outputstreamwriter':'android.permission.WRITE_EXTERNAL_STORAGE',
    'outputstream':'android.permission.WRITE_EXTERNAL_STORAGE',
    'sendsms':'android.permission.SEND_SMS',
}


def main(logsPath,path):
    logs = open(logsPath).read()
    logs = logs.split('\n')

    start = datetime.now()
    apklist = getAPKFileList(path)


    for path in apklist:
        # start = datetime.now()
        app = applicationInfo.application(path)
        res = app.getInformation()
        if res == 0:
            print("Failed to analyze the APK [" + path + "]. Terminate the analysis.")
            sys.exit(1)
        apps.append(app)
        names.append(app.getPackage())

        # end = datetime.now()
        # print "------------------time--------------"
        # print end - start
        # print os.path.getsize(path)/float(1024 * 1024)
        # print "------------------time--------------"



    intents = []
    intent = logAnalysis.Intent()

    file = open('../result/path.txt', 'a+')

    # collect logs
    for log in logs:
        file.write(log)

        if log.find(':') == -1:
            continue

        id1, id2 = logAnalysis.getProcessId(log)

        tag = log.split(':')[1].strip()

        if len(log.split(':')) < 3:
            content = ''
        else :
            content = log.split(':')[2].strip()
        if tag == 'intentTaint':
            if len(intent.getIntentTemp()) == 0:  # 如果前面没有出现intentleak，说明是开始，把前一个intent信息结束，然后创建新的
                if logAnalysis.intentJudge(intent,names) == True:  # 如果发送者和接受者存在一个是app ，就记录Intent
                    intent.clearTaintTemp()
                    intent.IntentTempClear()
                    logAnalysis.findRealSource(intent,intents)
                    intents.append(intent)
                    # if intent.getPrintState() == False:
                    #     intent.printIntentInfomation()
                intent = logAnalysis.Intent()

            # 不管前面有没有intentleak，这里都需要记录leak信息
            intent.addIntentTemp(tag=content, pid=id1)

        elif tag == 'intentSender-fromPackage':

            temp = intent.getIntentTemp()
            newtemp = []
            for it in temp:
                if it['pid'] == id1:
                    newtemp.append(it['tag'].lower())
            # 如果前面出现了intentleak，去掉不是app中的信息，其他的加入到intent中
            if len(temp) > 0:
                intent.setSenderPid(id1)
                intent.setIntentLeak(newtemp)
            else:  # 前面没有出现intentleak，结束前一个intent，创建新的
                if logAnalysis.intentJudge(intent,names) == True:  # 如果发送者和接受者存在一个是app ，就记录Intent
                    intent.clearTaintTemp()
                    intent.IntentTempClear()
                    logAnalysis.findRealSource(intent, intents)
                    intents.append(intent)
                    # if intent.getPrintState() == False:
                    #     intent.printIntentInfomation()

                intent = logAnalysis.Intent()
                intent.setSenderPid(id1)
            # 把temp中的信息清除掉
            intent.clearIntentTemp()

        if intent.getSenderPid() != '':
            flag, intent = logAnalysis.intentEvent(intent, log)

    # 最后一个intent处理
    intent.clearTaintTemp()
    intent.IntentTempClear()
    logAnalysis.findRealSource(intent, intents)
    intents.append(intent)

    for intent in intents:
        intent.printIntentInfomation()

    intents = logAnalysis.formatIntents(intents)

    intents = logAnalysis.performPolicy(apps, intents, names)
    #
    # # 显式结果
    # for intent in intents:
    #     intent.printIntentInfomation()

    print "--------------------"
    print len(intents)
    end = datetime.now()
    # t=end-start
    # t = str(t)[6:]
    # print t
    # return float(t)


def getAPKFileList(path):
    pathlist = []
    for root,dirs,files in os.walk(path):
        for file in files:
            if os.path.splitext(file)[-1] == '.apk':
                filepath = os.path.join(root,file)
                pathlist.append(filepath)
    return pathlist




#logsPath = '../source/logs.txt'
#apkPath = '../apk/'

argc = len(sys.argv)
if argc!=3:
    sys.exit(-1)

logsPath = sys.argv[1]
apkPath = sys.argv[2]


main(logsPath,apkPath)

