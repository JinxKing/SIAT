# encoding: utf-8
"""
@project = collusionAttackDetector
@file = Intent
@author = Jinz
@create_time = 2018/12/19

"""
import zipfile
from xml.dom import minidom
from utils import AXMLPrinter
import sys

class Ifilter:
    def __init__(self,package,componentName,componentType):
        self.package = package
        self.componentName = componentName
        self.componentType = componentType


class application:
    def __init__(self,filename):
        self.filename = filename
        self.packageNames = []
        self.mActivity = None
        self.filters = []
        self.inner = []
        self.outer = []
        self.recvs = {}
        self.services = {}
        self.activities = {}
        self.mainActivity=''
        self.permissions = []


    def getInformation(self):
        xml = {}
        error = True
        try:
            zip = zipfile.ZipFile(self.filename)

            for i in zip.namelist():
                if i == "AndroidManifest.xml":
                    try:
                        xml[i] = minidom.parseString(zip.read(i))
                    except:
                        xml[i] = minidom.parseString(AXMLPrinter(zip.read(i)).getBuff())

                    for item in xml[i].getElementsByTagName('manifest'):
                        self.packageNames.append(str(item.getAttribute("package")))

                    # for item in xml[i].getElementsByTagName('permission'):
                    #     self.enfperm.append(str(item.getAttribute("android:name")))

                    for item in xml[i].getElementsByTagName('uses-permission'):
                        self.permissions.append(str(item.getAttribute("android:name")))

                    for item in xml[i].getElementsByTagName('service'):
                        service = str(item.getAttribute("android:name"))
                        self.services[service] = {}
                        self.services[service]['action'] = list()
                        self.services[service]['category'] = list()

                        for child in item.getElementsByTagName('action'):
                            self.services[service]['action'].append(str(child.getAttribute("android:name")))
                        for child in item.getElementsByTagName('category'):
                            self.services[service]['category'].append(str(child.getAttribute("android:name")))

                    for item in xml[i].getElementsByTagName('receiver'):
                        reciver = str(item.getAttribute("android:name"))
                        self.recvs[reciver] = {}
                        self.recvs[reciver]['action'] = list()
                        self.recvs[reciver]['category'] = list()

                        for child in item.getElementsByTagName('action'):
                            self.recvs[reciver]['action'].append(str(child.getAttribute("android:name")))
                        for child in item.getElementsByTagName('category'):
                            self.recvs[reciver]['category'].append(str(child.getAttribute("android:name")))

                    for item in xml[i].getElementsByTagName('activity') + xml[i].getElementsByTagName('activity-alias'):
                        activity = str(item.getAttribute("android:name"))
                        self.activities[activity] = {}
                        self.activities[activity]["actions"] = list()
                        self.activities[activity]["category"] = list()

                        for child in item.getElementsByTagName('action'):
                            self.activities[activity]["actions"].append(str(child.getAttribute("android:name")))
                        for child in item.getElementsByTagName('category'):
                            self.activities[activity]["category"].append(str(child.getAttribute("android:name")))


                    for activity in self.activities:
                        for action in self.activities[activity]["actions"]:
                            if action == 'android.intent.action.MAIN':
                                self.mainActivity = activity
                    error = False

                    break

            if (error == False):
                return 1
            else:
                print 'application analysis false.'
                return 0
        except Exception,err:
            print "anaysis error:"
            print sys.exc_info()[0]
            return 0

    def getMainActivity(self):
        return self.mainActivity

    def getActivities(self):
        return self.activities

    def getRecvActions(self):
        return self.recvsaction

    def getPackage(self):
        return self.packageNames[0]

    def getPermissions(self):
        return self.permissions




