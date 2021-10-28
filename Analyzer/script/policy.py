# encoding: utf-8
"""
@project = collusionAttackDetector
@file = policy
@author = Jinz
@create_time = 2019/1/21
policy of detect collusion attack
"""
import detect

dataContactPerm = {
    'deviceId':'android.permission.READ_PHONE_STATE',
    'location_gps':'android.permission.ACCESS_FINE_LOCATION',
    'location_net':'android.permission.ACCESS_FINE_LOCATION',
    'phone number':'',
    'location_last':'',
    'sms':'',
    'browse-mark':'',
    'simserianumber':'android.permission.READ_PHONE_STATE',
    'subscriberId':'android.permission.READ_PHONE_STATE',
    '':'android.permission.WRITE_EXTERNAL_STORAGE',
}


def performPolicy(appA,appB,intents):

    intent = detect.Intent()
    intent.getIntentLeak()
    bLack = []
    for intent in intents:
        sender = intent.getSenderPackage()
        rcver = intent.getReceiverPackage()
        taints = intent.getIntentLeak()
        if len(taints)!=0:
            for t in taints:
                bLackOrNot()


