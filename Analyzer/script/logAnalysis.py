# encoding: utf-8
"""
@project = collusionAttackDetector
@file = detect
@author = Jinz
@create_time = 2018/12/19

"""

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

def getProcessId(log):
    str1 = log.split(':')[0]
    id1 = str1[str1.find('(') + 1:str1.find(")")].strip()

    if 'intentTaint' in log.split(':')[1] or 'taintLeak' in log.split(':')[1]:
        id2 = ''
    else:
        str2 = log.split(':')[-1]
        id2 = str2.split('-')[0].strip()
    id1.strip()
    id2.strip()
    return id1, id2

def findRealSource(intent,intents):  # 此时intent还没有加入到intents中
    taintLeak = intent.getTaintLeak()
    if len(taintLeak) == 0: return  # 如果没有发生taintleak就直接返回
    intentLeak = intent.getIntentLeak()
    for dict in taintLeak:
        tag = dict['tag']
        tag = tag.lower()
        if tag in intentLeak:  # 如果intent中包含了改污点，表示这个污点数据和intent中的一致
            source = intent.getSenderComponent()
            intent.addTaintLeakSource({'tag':tag,'source':source})
        else:
            for i in range(-1,0-len(intents),-1):
                it = intents[i]
                taintLeak1 = it.getTaintLeak()
                if len(taintLeak1) != 0 :
                    for dict in taintLeak1:
                        if tag ==dict['tag']: # 如果taintleak不为空而且tag就在里面，就把它的source作为自己的source
                            source = it.getSourceofTaint()
                            intent.addTaintLeakSource({'tag': tag, 'source': source})
                else:   # 如果taintleak中没有这个tag，就看看intentleak里有没有，如果有就作为自己的source
                    intentLeak = it.getIntentLeak()
                    if tag in intentLeak:  # 如果intent中包含了改污点，表示这个污点数据和intent中的一致
                        source = intent.getSenderComponent()
                        intent.addTaintLeakSource(tag, source)





def intentJudge(intent,names):
    # intent sender 和receiver是我们关心的app
    senderName = intent.getSenderPackage()
    rcvNames = intent.getReceiverPackage()

    try:
        names.index(senderName)
        return True
    except:
        pass

    for item in rcvNames:
        try:
            names.index(item)
            return True
        except:
            pass

    return False


def intentEvent(intent, log):
    flag = False
    senderId = intent.getSenderPid()
    receiverIds = intent.getReceiverPid()
    id1, id2 = getProcessId(log)

    if len(log.split(':'))<=2 and 'libcore.os.write' in log:
        leakMethod = 'writeOutput'
        words = log.split(' ',7)
        taintTag = words[6]
        taintContent = words[7][5:-1]

        for i in range(len(taintTag) - 2, 8):
            taintTag = taintTag[0:2] + '0' + taintTag[2:]
        file = open('../source/taintTag.txt')
        for item in file.readlines():
            item = item.strip('\n')
            if taintTag == item.split(':')[1].strip():
                taintTag = item.split(':')[0].strip()
                break
        file.close()
        log = log.split(':')[0]+": taintLeak: " + leakMethod + '-' + taintTag + '-' + taintContent


    tag = log.split(':')[1].strip()
    try:
        content = log.split(':', 2)[2].strip()
    except:
        return flag, intent

    content_pid = ''
    content_mes = ''
    if content.find('-') != 0:
        content_pid = content.split('-')[0].strip()
        content_mes = content.split('-')[-1].strip()

    if tag in 'intentSender-fromPackage' and id1 == senderId:
        intent.setSenderPackage(content)
        flag = True
    elif tag in 'intentSender-fromComponent' and id1 == senderId:
        if content.startswith('.'):
            content = intent.getSenderPackage()+content
        intent.setSenderComponent(content)
        flag = True
    elif tag in 'intentSender-receivertype' and id1 == senderId:
        intent.setRcverType(content)
        flag = True
    elif tag in 'intentAttr-toComponent' and content_pid == senderId:
        intent.setToComponent(content_mes)
        flag = True
    elif tag in 'intentAttr-action' and content_pid == senderId:
        intent.setAction(content_mes)
        flag = True
    elif tag in 'intentAttr-category' and content_pid == senderId:
        intent.setCategories(content_mes)
        flag = True
    elif tag in 'intentAttr-type' and content_pid == senderId:
        intent.setIntentType(content_mes)
        flag = True
    elif tag in 'intentAttr-data' and content_pid == senderId:
        intent.setIntentData(content_mes)
        flag = True
    elif tag in 'intentAttr-scheme' and content_pid == senderId:
        intent.setIntentScheme(content_mes)
        flag = True

    elif tag.split('-')[0] == 'intentGet'and existInList(id1,receiverIds) == False:
        if tag in 'intentGet-action':
            intent.addIntentGetTemp(['action',{'pid': id1, 'content': content}])
        elif tag in 'intentGet-data':
            intent.addIntentGetTemp(['data', {'pid': id1, 'content': content}])
        elif tag in 'intentGet-hasExtra':
            intent.addIntentGetTemp(['hasextra', {'pid': id1, 'content': content}])
        elif tag in 'intentGet-type':
            intent.addIntentGetTemp(['type', {'pid': id1, 'content': content}])
        elif tag in 'intentGet-scheme':
            intent.addIntentGetTemp(['scheme', {'pid': id1, 'content': content}])
        elif tag in 'intentGet-hasCategory':
            intent.addIntentGetTemp(['hascate', {'pid': id1, 'content': content}])
        elif tag in 'intentGet-getCategories':
            intent.addIntentGetTemp(['cates', {'pid': id1, 'content': content}])
    elif tag in 'intentGet-action' and existInList(id1,receiverIds) == True:
        intent.setActionGet({'pid':id1,'content':content})
        flag = True
    elif tag in 'intentGet-data' and existInList(id1,receiverIds) == True:
        intent.setDataGet({'pid':id1,'content':content})
        flag = True
    elif tag in 'intentGet-hasExtra' and existInList(id1,receiverIds) == True:
        intent.addHasExtra({'pid':id1,'content':content})
        flag = True
    elif tag in 'intentGet-type' and existInList(id1,receiverIds) == True:
        intent.setTypeGet({'pid':id1,'content':content})
        flag=True
    elif tag in 'intentGet-scheme' and existInList(id1,receiverIds) == True:
        intent.setschemeGet({'pid':id1,'content':content})
        flag = True
    elif tag in 'intentGet-hasCategory' and existInList(id1,receiverIds) == True:
        intent.addHasCate({'pid':id1,'content':content})
        flag = True
    elif tag in 'intentGet-getCategories' and existInList(id1,receiverIds) == True:
        intent.setCategoriesGet({'pid':id1,'content':content})
        flag = True
    elif tag in 'query-matchComponent':
        component = content.split('-')[0]
        intent.addMatchComponent(component)
        intent.addMatchInfo(content.split('-'))
        flag = True
    elif tag in 'ifilterMatch-package' and content_pid == senderId:
        intent.addReceiverPackage(content_mes)
        flag = True
    elif tag in 'ifliterMatch-component' and content_pid == senderId:
        intent.addReceiverComponent(content_mes)
        flag = True
    elif tag in 'ifliterMatch-callingPid' and content_pid == senderId:
        receiverId = content.split("-")[1]
        if receiverId == senderId:
            intent.addReceiverPid(receiverId,intent.getSenderPackage())
    elif tag in 'receiver-packageName' and existInList(content_mes,intent.getReceiverPackage()) == True:
        receiverId = content_pid
        intent.addReceiverPid(receiverId,content_mes)
        intent.setReceiverLog(True)
        flag = True

    elif tag in 'taintLeak' and content.split('-')[1].isdigit() == False:

        leakMethod = content.split('-')[0]
        taintTag = content.split('-')[1]
        taintContent = content.split('-', 2)[-1]

        if existInList(item=id1,list=receiverIds)==True:
            intent.addTaintLeak(content=taintContent, tag=taintTag, method=leakMethod,pid=id1)
        else:
            intent.addTaintTemp(tag=taintTag, content=taintContent, pid=id1, method=leakMethod)
        flag = True


    if flag == True:
        intent.appendLog(log)

    return flag, intent

def existInList(item,list):
    newlist = []

    if len(list) > 0 and type(list[0]) is type(list):
        for it in list:
            newlist.append(it[0])
        list = newlist
    try:
        list.index(item)
        return True
    except:
        return False


def formatIntents(intents):
    newList = []
    for i in range(len(intents)):
        intent = intents[i]

        if intent.getSenderPackage() == 'com.android.launcher' or intent.getSenderPackage() == 'android': # android作为发送者也跳过
            continue
        elif  len(intent.getMatchComponent()) == 0: # 匹配的组件 < 1 就跳过
            newList.append(intent)
            continue
        elif len(intent.getReceiverComponent())!=0: # 不用resolveActivity的转发，直接匹配的了
            newList.append(intent)
            continue

        intentRcv = intents[i+1]

        intent.setReceiverPackage(intentRcv.getReceiverPackage())
        intent.setReceiverComponent(intentRcv.getReceiverComponent())
        intent.setReceiverLeak(intentRcv.getReceiverLeak())
        intent.setTaintLeak(intentRcv.getTaintLeak())

        newList.append(intent)

    return newList


class Intent:
    type_inner = 'inter-component'
    type_outer = 'inter-app'

    def __init__(self):
        self.senderPid = ''
        self.receiverPid = []   # [['1','pkgName1'],['2','pkgName2']]
        self.senderPackage = ''
        self.senderComponent = ''
        self.receiverPackage = []
        self.receiverComponent = []
        self.intentLeak = []
        self.receiverLeak = []
        self.taintLeak = []
        self.intent_action = ''
        self.intent_categories = []
        self.intent_type = ''
        self.intent_toComponent = ''
        self.receiverLog = False
        self.transferType = []
        self.log = []
        self.taintTemp = []
        self.intentTemp = []
        self.printYet = False
        self.rcverType = ''
        self.intent_data=''
        self.intent_scheme = ''
        self.attackType = ''
        self.attackers = []
        self.matchComponent = []
        self.matchInfo = []  # 存储匹配组件的信息，[0]:组件名， [1]:优先级 [2]:preferredOrder [3]:isDefault
        self.senderLackPerms = []
        self.receiverLackPerms = []
        self.victim = []
        self.intent_action_get = {}
        self.intent_type_get = {}
        self.intent_categories_get = {}
        self.intent_data_get = {}
        self.intent_scheme_get={}
        self.intent_hasExtra_get = []
        self.intent_hasCate_get = []
        self.intentGetTemp = []
        self.taintLeakSource=[]

    def IntentTempClear(self): # 存到地方再清除
        for item in self.intentGetTemp:
            tag = item[0]
            content = item[1]
            pid = content['pid']
            if existInList(pid,self.getReceiverPid()) == False:
                continue
            if tag == 'action':
                self.setActionGet(content)
            elif tag == 'type':
                self.setTypeGet(content)
            elif tag == 'cates':
                self.setCategoriesGet(content)
            elif tag == 'scheme':
                self.setschemeGet(content)
            elif tag == 'hasextra':
                self.addHasExtra(content)
            elif tag == 'hascate':
                self.addHasCate(content)
            elif tag == 'data':
                self.setDataGet(content)
        self.intentGetTemp=[]

    def addIntentGetTemp(self,data):
        self.intentGetTemp.append(data)

    def addHasCate(self,cate):
        self.intent_hasCate_get.append(cate)

    def getHasCate(self):
        return self.intent_hasCate_get

    def addHasExtra(self,extra):
        self.intent_hasExtra_get.append(extra)
    def getHasExtra(self):
        return self.intent_hasExtra_get

    def setschemeGet(self,scheme):
        self.intent_scheme_get = scheme

    def getSchemeGget(self):
        return self.intent_scheme_get

    def setDataGet(self,date):
        self.intent_data_get = date

    def getDataGget(self):
        return self.intent_data_get

    def setCategoriesGet(self,cate):
        self.intent_categories_get = cate

    def getCategoriesGget(self):
        return self.intent_categories_get

    def setTypeGet(self,type):
        self.intent_type_get = type

    def getTypeGet(self):
        return self.intent_type_get

    def setActionGet(self,action):
        self.intent_action_get = action

    def getActionGet(self):
        return self.intent_action_get

    def addVictim(self,vic):
        self.victim.append(vic)
    def setVictim(self,vic):
        self.victim = vic
    def getVictim(self):
        return self.victim

    def setSenderLackPerms(self,pms):
        self.senderLackPerms = pms
    def getSenderLackPerms(self):
        return self.senderLackPerms
    def setReceiverLackPerms(self,pms):
        self.receiverLackPerms = pms
    def getReceiverLackPerms(self):
        return self.receiverLackPerms

    def addMatchInfo(self,info):
        self.matchInfo.append(info)
    def getMatchInfo(self):
        return self.matchInfo

    def addMatchComponent(self,cp):
        self.matchComponent.append(cp)

    def getMatchComponent(self):
        return self.matchComponent

    def setAttackers(self,attackers):
        self.attackers = attackers
    def addAttackers(self,attacker):
        self.attackers.append(attacker)
    def getAttackers(self):
        return self.attackers

    def setAttackType(self,type):
        self.attackType = type

    def getAttackType(self):
        return self.attackType

    def setIntentData(self,data):
        self.intent_data = data
    def getIntentData(self):
        return self.intent_data

    def setIntentScheme(self,scheme):
        self.intent_scheme = scheme
    def getIintentScheme(self):
        return self.intent_scheme

    def setRcverType(self, type):
        self.rcverType = type

    def getRcverType(self):
        return self.rcverType

    def setPrintState(self, state):
        self.printYet = state

    def getPrintState(self):
        return self.printYet

    def setIntentTemp(self, temp):
        self.intentTemp = temp

    def addIntentTemp(self, tag, pid):
        tupe = {'tag': tag, 'pid': pid}
        self.intentTemp.append(tupe)

    def getIntentTemp(self):
        return self.intentTemp

    def clearIntentTemp(self):
        self.intentTemp = []

    def clearTaintTemp(self):
        for item in self.getTaintTemp():
            tag = item.get('tag')
            content = item.get('content')
            pid = item.get('pid')
            leakMethod = item.get('method')

            if existInList(pid, self.getReceiverPid()) == True:
                self.addTaintLeak(tag=tag, content=content, method=leakMethod, pid=pid)
        self.taintTemp = []

    def addTaintTemp(self, tag, content, pid, method):
        dict = {'tag': tag, 'content': content, 'pid': pid, 'method': method}
        self.taintTemp.append(dict)

    def getTaintTemp(self):
        return self.taintTemp

    def setTransferType(self, type):
        self.transferType = type

    def getTransferType(self):
        return self.transferType

    def appendLog(self, l):
        self.log.append(l)

    def getLog(self):
        return self.log

    def setReceiverLog(self, rl):
        self.receiverLog = rl

    def isExistReceiverLog(self):
        return self.receiverLog

    def setToComponent(self, comp):
        self.intent_toComponent = comp

    def getToComponent(self):
        return self.intent_toComponent

    def setIntentType(self, intentType):
        self.intent_type = intentType

    def getIntentType(self):
        return self.intent_type

    def setCategories(self, category):
        self.intent_categories.append(category)

    def getCategories(self):
        return self.intent_categories

    def setAction(self, action):
        self.intent_action = action

    def getAction(self):
        return self.intent_action

    def setSenderPid(self, pid):
        self.senderPid = pid

    def getSenderPid(self):
        return self.senderPid

    def addReceiverPid(self, pid,name):
        self.receiverPid.append([pid,name])

    def getReceiverPid(self):
        return self.receiverPid

    def setIntentLeak(self, intentLeak):
        self.intentLeak = intentLeak


    def getIntentLeak(self):
        return self.intentLeak

    def setReceiverLeak(self, receiverLeaks):
        self.receiverLeak = receiverLeaks

    def addReceiverLeak(self, receiverLeak):
        self.receiverLeak.append(receiverLeak)

    def getReceiverLeak(self):
        return self.receiverLeak

    def addTaintLeak(self, tag, content, method,pid):
        tag = tag.lower()
        dict = {'tag': tag, 'content': content, 'method': method,'pid':pid}
        self.taintLeak.append(dict)

    def getTaintLeak(self):
        return self.taintLeak

    def setSenderPackage(self, name):
        self.senderPackage = name

    def getSenderPackage(self):
        return self.senderPackage

    def setSenderComponent(self, name):
        self.senderComponent = name

    def getSenderComponent(self):
        return self.senderComponent

    def setReceiverPackage(self, names):
        self.receiverPackage = names

    def addReceiverPackage(self, name):
        self.receiverPackage.append(name)

    def getReceiverPackage(self):
        return self.receiverPackage

    def setReceiverComponent(self, names):
        self.receiverComponent = names

    def addReceiverComponent(self, name):
        self.receiverComponent.append(name)

    def getReceiverComponent(self):
        return self.receiverComponent

    def addTaintLeakSource(self,tag,source):
        dict = {'tag': tag, 'source': source}
        self.taintLeakSource.append(dict)
    def getSourceofTaint(self,tag):
        for dict in self.taintLeakSource:
            if dict['tag'] == tag:
                return dict['source']

    def printIntentInfomation(self):
        self.printYet = True
        print '\n------intent send------'
        if self.senderComponent[0] == '.':
            print 'sender: %s%s' % (self.senderPackage,self.senderComponent)
        else:
            print 'sender: %s' % self.senderComponent
        print 'receiver type: '+self.rcverType
        if len(self.intentLeak) > 0:
            for item in self.intentLeak:
                print 'taint in intent: ' + item
        if self.intent_toComponent != '':
            print 'intent aimComponent: ' + self.intent_toComponent
        if len(self.getCategories()) > 0:
            for item in self.getCategories():
                print 'self category: ' + item
        if self.intent_action != '':
            print 'intent action: ' + self.intent_action
        if self.intent_data != '':
            print 'intent data: ' +self.intent_data
        if self.intent_scheme!='':
            print 'intent scheme: '+self.intent_scheme
        if self.intent_type != '':
            print 'intent type: ' + self.intent_type
        if len(self.matchComponent)>0:
            print 'matchComponent: '+str(self.matchComponent)

        for i in range(len(self.receiverComponent)):
            package = self.receiverPackage[i]
            component = self.receiverComponent[i]
            if component[0] == True:
                print 'receiver: %s%s' % (package, component)
            else:
                print 'receiver: %s ' % component

        if self.intent_action_get.has_key('content'):
            pid = self.intent_action_get['pid']
            for it in self.getReceiverPid():
                if pid == it[0]:
                    pid = it[1]
                    break
            content = self.intent_action_get['content']
            print 'receiver(%s) get action(%s)' % (pid,content)

        if self.intent_categories_get.has_key('content'):
            pid = self.intent_categories_get['pid']
            for it in self.getReceiverPid():
                if pid == it[0]:
                    pid = it[1]
                    break
            content = self.intent_categories_get['content']
            print 'receiver(%s) get categories' % (pid)

        if self.intent_data_get.has_key('content'):
            pid = self.intent_data_get['pid']
            for it in self.getReceiverPid():
                if pid == it[0]:
                    pid = it[1]
                    break
            content = self.intent_data_get['content']
            print 'receiver(%s) get data(%s)' % (pid,content)

        if self.intent_type_get.has_key('content'):
            pid = self.intent_type_get['pid']
            for it in self.getReceiverPid():
                if pid == it[0]:
                    pid = it[1]
                    break
            content = self.intent_type_get['content']
            print 'receiver(%s) get type(%s)' % (pid,content)

        if self.intent_scheme_get.has_key('content'):
            pid = self.intent_scheme_get['pid']
            for it in self.getReceiverPid():
                if pid == it[0]:
                    pid = it[1]
                    break
            content = self.intent_scheme_get['content']
            print 'receiver(%s) get scheme(%s)' % (pid,content)

        if len(self.intent_hasCate_get)>0:
            for item in self.intent_hasCate_get:
                pid = item['pid']
                for it in self.getReceiverPid():
                    if pid == it[0]:
                        pid = it[1]
                        break
                content = item['content']
                print 'receiver(%s) search category(%s)'%(pid,content)

        if len(self.intent_hasExtra_get)>0:
            for item in self.intent_hasExtra_get:
                pid = item['pid']
                for it in self.getReceiverPid():
                    if pid == it[0]:
                        pid = it[1]
                        break
                content = item['content']
                print 'receiver(%s) search extra(%s)'%(pid,content)

        if len(self.taintLeak) > 0:
            for item in self.taintLeak:
                tag = item['tag']
                content = item['content']
                method = item['method']
                source = self.getSourceofTaint(tag)
                print'======='
                print 'taintleak-method: %s' % method
                print 'taintleak-tag: %s' % tag
                print 'taintleak-content: %s' % content
                print 'taintleak-source:%s' % source
                print'======='
        if self.attackType!='':
            attackers = ''
            victim = ''
            for it in self.attackers:
                if type(it) == type(self.attackers):
                    attackers = "(%s,%s),"%(it[0],it[1])
                else:
                    attackers = attackers+','+it
            for it in self.victim:
                victim = victim+','+it
            print '***'
            print 'attackType: %s' % self.attackType
            print 'attackers: %s' % attackers.strip(',')
            print 'victim: %s' % victim.strip(',')
            print '***'



def performPolicy(apps,intents,names):
    hijack = []
    spoof = []
    collusion = []

    intent = Intent()
    intent.getIntentLeak()
    bLack = []
    for intent in intents:
        sender = intent.getSenderComponent()
        rcvers = intent.getReceiverPackage()
        intentTaints = intent.getIntentLeak()
        taintLeak = intent.getTaintLeak()



        if senderChooseAim(intent) == True :
            if len(permissionComplementary(intent,apps))>0:
                intent.addAttackers([intent.getSenderPackage(),intent.getReceiverPackage()])
                intent.setAttackType('collusion-pmsCpl')
                intent.addVictim('user')
                collusion.append(intent)
            continue

        cps = sysAttribute(intent,names)
        if len(cps)>0:     # 证明intent是sender给系统app的
            intent.setAttackType('hijack sys')
            intent.addVictim(intent.getSenderComponent())
            intent.setAttackers(cps)
            hijack.append(intent)
            continue

        cps = matchOwnRcver(intent,names)
        if len(cps)>0:     # 证明intent是sender发送给自己的，内部组件可以匹配
            intent.setAttackers(cps)
            intent.addVictim(sender)
            intent.setAttackType('hijack own')
            hijack.append(intent)
            continue

        dicts = rcvPmsLack(intent,apps)
        if len(dicts) > 0 or inputdataExist==True and len(senderPmsLack(intent,apps)) == 0:  # 有污点数据从sender->rcver 而且 rcvapp不能自己获得污点数据,且rvc不涉及spoof
            intent.setReceiverLackPerms(dicts)      # {'name':component,'permissions':[pm1,pm2]}
            intent.addVictim(sender)
            intent.setAttackType('hijack taint-pmlack')
            for item in dicts:
                intent.addAttackers(item['name'])
            hijack.append(intent)  # intent劫持
            continue

        vics = receiverToReceiver(intent, intents)
        if len(vics)>0:  # 如果组件有接收本应用发送的intent，说明A是伪造的
            intent.setVictim(vics)   # 返回的rst是victim
            intent.addAttackers(sender)
            intent.setAttackType('spoof A-A')
            spoof.append(intent)
            continue

        dicts = senderPmsLack(intent,apps)
        if len(dicts)>0 and len(rcvPmsLack(intent,apps))==0:  # 在receiver涉及的敏感api，sender中没有权限
            intent.setSenderLackPerms(dict)   # rst = [{'name':componentName,'permissions':[pm1,pm2]}]
            intent.addAttackers(sender)
            for item in dicts:
                intent.addVictim(item['name'])
            intent.setAttackType('spoof pmLack')
            spoof.append(intent)
            continue

        cps = launchPrivateComponent(intent, intents)
        if len(cps)>0:   # 私有组件启动
            intent.addAttackers(cps[0])
            intent.addVictim(cps[1])
            intent.setAttackType('spoof privateComponent')
            spoof.append(intent)
            continue

        cps = communicateEachOther(intent,intents)
        if len(cps)>0:  # AB之间相互交流
            intent.setAttackers(cps)
            intent.setAttackType('collusion-cm')
            intent.addVictim('user')
            collusion.append(intent)
            continue

        cps = permissionComplementary(intent, apps)
        if len(cps)>0: # 权限互补
            intent.setAttackers(cps)
            intent.setAttackType('collusion-pmsCpl')
            intent.addVictim('user')
            collusion.append(intent)
            continue
    return intents

def senderChooseAim(intent):
    action = intent.getAction()
    categories = intent.getCategories()

    if len(intent.getReceiverComponent()) != 1 or intent.getReceiverPackage()[0] == intent.getSenderPackage():
        return False

    rcv = intent.getReceiverPackage()[0]
    if rcv in action:
        return True
    for cate in categories:
        if rcv in cate:
            return True

    return False


def inputdataExist(intent):
    intent = Intent()
    intent.getReceiverLeak()
    for item in intent.getReceiverLeak():
        if item.lower()=='inputtext':
            return True
    return False

def launchPrivateComponent(intent,intents):
    rst = []
    try:
        index = intents.index(intent)
        intentAfter = intents[index+1]
        sender1 = intentAfter.getSenderComponent()
        rcv1 = intentAfter.getReceiverComponent()[0]
        rcvs = intent.getReceiverComponent()
        if sender1 in rcvs and getRcvCompPkgName(rcv1,intent.getReceiverPackage())==intent.getSenderPackage():
            rst.append(intent.getSenderComponent())
            rst.append(rcv1)
            return rst   # rst = [attacker,victim]
    except:
        pass
    return rst


def permissionComplementary(intent,apps):  # 返回rst = [[cp1,cp2],[cp3,cp4]]
    rst = []
    rcvLack = []
    sdrLack = []
    for it in rcvPmsLack(intent, apps):
        rcvLack.append(it['name'])
    for it in senderPmsLack(intent,apps):
        sdrLack.append(it['name'])

    sender = intent.getSenderComponent()
    rcvers = intent.getReceiverComponent()

    for rcver in rcvers:
        if rcver in sdrLack and rcver in rcvLack:
            rst = [[intent.getSenderPackage(),getRcvCompPkgName(rcver,intent.getReceiverPackage())]]
    return rst

def communicateEachOther(intent,intents): # rst = [[cp1,cp2],[cp3,cp4]]
    rst = []
    senderPkg = intent.getSenderPackage()
    rcvPkgs = intent.getReceiverPackage()

    for item in intents:
        if item.getSenderPackage() in rcvPkgs and senderPkg in item.getReceiverPackage() and senderPkg!=item.getSenderPackage():
            rst.append([senderPkg,item.getSenderPackage()])
    return rst


def receiverToReceiver(intent,intents):  # rst = [cp1,cp2,...]  victim
    rst = []
    sender = intent.getSenderPackage()
    receivers = intent.getReceiverComponent()
    pkgNames = intent.getReceiverPackage()
    for i in range(len(receivers)):
        receiver = receivers[i]
        pkgName = pkgNames[i]
        for intent in intents:
            rcvs = intent.getReceiverComponent()
            sder = intent.getSenderComponent()
            if pkgName in sder and receiver in rcvs and sender!=getRcvCompPkgName(receiver,pkgNames):  # rcver 有接收过自己发送的intent
                rst.append(receiver)

    return rst



def matchOwnRcver(intent,names): # rst = [cp1,cp2,...]  attacker
    rst = []
    senderPackage = intent.getSenderPackage()
    RcverType = intent.getRcverType()
    if RcverType == 'broadcast':
        components = intent.getReceiverComponent()
        exit = False
        for component in components:
            if senderPackage in component:   # 组件名中含有sender名
                exit = True
        if exit == True:
            for component in components:
                if senderPackage not in component and existInList(component,names) ==True:   # 组件名里不含有sender名，且是app的应用，是攻击者
                    return True
    elif len(intent.getMatchComponent())>0: # 接受者是activity和service，且匹配组件有多个
        flag = False
        attackers = []
        for cp in intent.getMatchComponent():
            if senderPackage in cp:
                flag == True
                break

        if flag == True:
            for cpN in intent.getMatchComponent():
                if senderPackage not in cp and getRcvCompPkgName(cp,intent.getReceiverPackage()) in names:
                    rst.append(cp)
    return rst

def getRcvCompPkgName(component,pkgNames):
    for name in pkgNames:
        if name in component:
            return name
    return ''

def sysAttribute(intent,names):
    rst = []
    action = intent.getAction()
    categories = intent.getCategories()
    sysActions = open('../source/action.txt').readlines()
    sysCategories = open('../source/category.txt').readlines()

    for i in range(len(sysActions)):
        sysActions[i] = sysActions[i].strip('\n')
    for i in range(len(sysCategories)):
        sysCategories[i] = sysCategories[i].strip('\n')

    flag = True
    for category in categories:
        if category not in sysCategories:
            flag = False
    if flag == False or action not in sysActions:
        return rst

    for cp in intent.getReceiverComponent():
        if getRcvCompPkgName(cp,intent.getReceiverPackage()) in names:
            rst.append(cp)

    return rst



# 判断发送者是否缺少接受者敏感api的权限
def senderPmsLack(intent, apps):
    leakTaints = intent.getTaintLeak()
    rcvers = intent.getReceiverComponent()
    rcvpkgs = intent.getReceiverPackage()
    senderPkg = intent.getSenderPackage()
    senderPms = []

    rst = []

    for it in apps:
        if it.getPackage == senderPkg:
            senderPms = it.getPermissions()
            break

    for i in range(len(rcvers)):
        rcvpkg = rcvpkgs[i]
        rcver = rcvers[i]
        if rcvpkg == senderPkg:
            continue

        for it in intent.getReceiverPid():
            pid = it[0]
            pkgName = it[1]
            lackPms = []
            if pkgName != rcvpkg:
                continue

            for taint in intent.getTaintLeak():
                if taint['pid'] == pid:
                    method = taint['method'].lower()
                    if dataContactPerm.has_key(method):
                        permission = dataContactPerm[method]
                    else:
                        continue
                    pms = []
                    if type(permission) == type(pkgName):
                        pms.append(permission)
                    else:
                        pms = permission

                    for pm in pms:
                        try:
                            senderPms.index(pm)
                        except:
                            lackPms.append(pm)
            if len(lackPms)> 0:
                rst.append({'name':rcver,'permissions':lackPms})

    return rst


# 判断rcv中是否有污点数据的权限，如果缺少返回False
def rcvPmsLack(intent,apps):
    rst = []
    senderPkg = intent.getSenderPackage()
    rcvpkgs = intent.getReceiverPackage()
    rcvs = intent.getReceiverComponent()
    taints = intent.getIntentLeak()
    for i in range(len(rcvpkgs)):
        pkgName = rcvpkgs[i]
        component = rcvs[i]
        pmRcv = []
        rcvLack = []
        if senderPkg == pkgName:  # app本应用中的交流跳过
            continue
        for it in apps:
            if it.getPackage() == pkgName:
                pmRcv =it.getPermissions()
                break
        for taint in taints:
            taint = taint.lower()
            if dataContactPerm.has_key(taint):
                permission = dataContactPerm[taint]
            else:
                continue
            pms = []
            if type(permission) == type(pkgName):
                pms.append(permission)
            else:
                pms = permission

            for pm in pms:
                try:
                    pmRcv.index(pm)
                except:
                    rcvLack.append(pm)
        if len(rcvLack)>0:
            rst.append({'name':component,'permissions':rcvLack})

    # rst : [{'rcv1':[pm1,pm2]},{'cp2':[pm1,pm2]},]
    return rst


