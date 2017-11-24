#!/usr/bin/env python

# -*- coding: utf-8 -*-

import pip
import sys
import os
import time
import atexit
import magic
import signal
import string
import shutil
import subprocess
import getpass
import socket
import requests
import base64
import ConfigParser
import logging
import thread
import socket
import hashlib
import ssl
import json
import urllib2
import datetime as dt

from signal import SIGTERM
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from os.path import basename
from os import walk
from time import localtime, strftime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if os.environ.get("UnitTestMacro"):
    print "UnitTestMacro : [%s]" % (os.environ["UnitTestMacro"])
    UNIT_TEST_MACRO = 1
else:
    UNIT_TEST_MACRO = 0

# REST daemon version string #
VERSION = "v1.0"

def install_modules():
    modules=["watchdog", "python-magic", "requests", "signal", "base64", "logging", "ConfigParser", "urllib3", "getpass"]
    for module in modules:
        pip.main(["install", module])

MAX_INDEX = 1000

hashmap = [None] * MAX_INDEX

HASH_INDEX = 0

DIR_SCAN_RUN_FLAG = False

DISK_FREE_SPACE_CHECK_FLAG = False

LOCAL_SCAN_DIRECTORY_INTERVAL = 0
# Holds the count of number of files submitted to the ATD 
file_counter = 0

continue_flag = True
#this holds the submission time to prepare the timer
submission_time = 0

SAMPLE_SUBMISSION_FLAG = False

last_file_counter_update_time = 0
# number of files present in bro extraction directory #
old_files_count_atStart = 0

file_move_path = ''
# file removal flag : whether to remove file or no #
FILE_REMOVE_FLAG = "NO"
# Silent mode on or off. 0 = OFF 1 = ON.
SILENT_MODE = 0

HIST_UPDATE_FLAG = 0

LOGOUT_RESULT = 0

HEARTBEAT_MISSED = 0

''' record script daemon start time. '''
SCRIPT_START_TIME = ""

''' declaring global variables for REST configuration '''
matdip = ""
username = ""
password = ""
analyzer_profile_id = 0
bro_sample_path = ""
bro_version = ""
silent_mode = ""
env_path = ""

''' help function to display for user '''
def help():
    print "usage:\t%s start | stop | restart | configure | status " % sys.argv[0]
    print "\tDescription: \n\t\tTo start | stop | restart | configure REST submission daemon. \n\t\tTo get the status of daemon using ststus command."
    print "usage:\t%s stats" % sys.argv[0]
    print "\tDescription: \n\t\tTo get details statistics of sample submission."
    sys.exit(2)

'''
    Check if provided arguments are sufficient to proceed.
'''
if (UNIT_TEST_MACRO != 1) and (len(sys.argv) != 2):
    help()
    sys.exit(1)

''' Bro directories '''
CONF_DIR = "/etc" + "/atd-bro/"
BRO_CONF_FILE = CONF_DIR + "atd-bro.conf"

'''
    At start | restart reading configuration file to check the installation path
    Other than start | restart option installation path will be considered as a HOME_DIR
'''
if len(sys.argv) == 2:
    if ('start' == sys.argv[1]) or ('restart' == sys.argv[1]) or ('stop' == sys.argv[1]) or ('stats' == sys.argv[1]):
        config = ConfigParser.ConfigParser()

        try:
            config.readfp(open(BRO_CONF_FILE))
        except IOError:
            print "\nError : Please do configure before using REST Submission daemon.\n"
            sys.exit(1)

        ''' Check if user has provided path to install files '''
        env_path = config.get('BRO CONFIG', 'Installation path')

        if env_path == "":
            ''' home directory '''
            HOME_DIR = os.path.expanduser('~')
        else:
            ''' Considering daemon home directory as user provided path '''
            HOME_DIR = env_path

        if os.path.exists(HOME_DIR):
            if not os.access(HOME_DIR, os.W_OK):
                print "ERROR : [%s] directory path should have Read-Write permissions." % (HOME_DIR)
        else:        
            os.makedirs(HOME_DIR)

        env_path = ""
    else:
        HOME_DIR = os.path.expanduser('~')
elif UNIT_TEST_MACRO == 1:
    HOME_DIR = os.path.expanduser('~')


''' Bro directories '''
CONF_DIR = "/etc" + "/atd-bro/"
LOG_DIR  = HOME_DIR + "/atd-bro/var/log/"
COUNTER_DIR = HOME_DIR + "/atd-bro/var/counter/"
#PID_DIR = HOME_DIR + "/atd-bro/pid/"
PID_DIR = "/var/run/"
SAMPLE_BACKUP_DIR = HOME_DIR + "/atd-bro/var/samples_backup/"


''' Bro files : configuration | log | counter '''
COUNTER_FILE = COUNTER_DIR + "/" + "fileCounter.txt"
COUNTER_HIST_FILE = COUNTER_DIR + "/" + "fileCounterHist.txt"
LOG_FILE = LOG_DIR + "bro.log"
PID_FILE = PID_DIR + "bro.pid"
BRO_CONF_FILE = CONF_DIR + "atd-bro.conf"

''' if this file is present at LOG_DIR then hash table content will be logged to log file for debugging purpoese '''
PRINT_HASH_FLAG = LOG_DIR + "loghash" 

''' login info : session releated details '''
loginInfo = {'rest_req':'', 'sesuser_enc':''}

''' device info stored in a directory to make it available to all classess members and functions to work with '''
ATDInfo = {'matdip':'','username':'','silent_mode':'','analyzer_profile_id':'','bro_sample_path':'','remove_file_on_submission':'','bro_version':'','env_path':''}

logger = ""

def check_access(path, mode):
    '''    
        modde - One of the constants :data:`os.F_OK`, :data:`os.R_OK`,
        :data:`os.W_OK`, :data:`os.X_OK`

    '''
    if not os.access(path, mode):
        print "User [%s] do not have permission to create directory [%s] "%(getpass.getuser(), path)
        sys.exit(0)

''' function to create bro rest submission daemon environment to store all related files of log | configuration | counter etc. '''
def create_bro_env():
    global HOME_DIR

    if check_access(HOME_DIR + "/atd-bro/",os.F_OK) and not os.path.exists(HOME_DIR + "/atd-bro/"):
        os.makedirs(HOME_DIR + "/atd-bro/")
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    if check_access(CONF_DIR,os.F_OK) and not os.path.exists(CONF_DIR):
        os.makedirs(CONF_DIR)
    if not os.path.exists(HOME_DIR + "/atd-bro/var/counter/"):
        os.makedirs(HOME_DIR + "/atd-bro/var/counter/")
    if check_access(PID_DIR, os.F_OK) and not os.path.exists(PID_DIR):
        os.makedirs(PID_DIR)
    if  check_access(SAMPLE_BACKUP_DIR,os.F_OK) and not os.path.exists(SAMPLE_BACKUP_DIR):
        os.makedirs(SAMPLE_BACKUP_DIR)


if UNIT_TEST_MACRO != 1:
    ''' creating bro rest submission daemon environment '''
    if ('start' == sys.argv[1]) or ('restart' == sys.argv[1]) or ('stop' == sys.argv[1]):
        create_bro_env()
    elif ('configure' == sys.argv[1]):
        if check_access(CONF_DIR, os.F_OK ) and not os.path.exists(CONF_DIR):
            os.makedirs(CONF_DIR)


''' Setting up the logger '''
def log_setup():
    global logger 
    global LOG_FILE
    logFile = LOG_FILE

    logger = logging.getLogger('myapp')

    if not os.path.exists("/var/log/bro/"):
        os.makedirs("/var/log/bro/")

    '''
        Rotating log file with size of 100Mb.
    '''
    hdlr = RotatingFileHandler(logFile, mode='a', maxBytes=(100*1000*1000), backupCount=10, encoding=None, delay=0)

    '''
        Value		Type of interval
        's'	    	Seconds
        'm'	    	Minutes
        'h'	    	Hours
        'd'	    	Days
        'w0'-'w6'	Weekday (0=Monday)
        'midnight'	Roll over at midnight

        will rotate logs 3 days once
    
    hdlr = TimedRotatingFileHandler(logFile, when="d", interval=3, backupCount=100, encoding=None, delay=0) 
    '''
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)

    return (0)

''' 
    Function used to check the file completion status 
    If file is still being extracted|downloaded from network interface,
    then next file will be choosed for submission.
    File which is skipped for now will be retried in next directory scan for submission.
'''
def isFileExctractionCompleted(samplePath):
    if os.path.exists(samplePath):
        statinfo = os.stat(samplePath)
        
        sampleModTime = statinfo.st_mtime
        currentSystemTime = time.time()

        accessTime = currentSystemTime - sampleModTime
        logger.info("sampleModifyTime : [%d] currentSystemTime : [%d] SampleAccessTime : [%d]" % (sampleModTime, currentSystemTime, accessTime))
        
        if (currentSystemTime - sampleModTime) < 1:
            ''' Need to skip the sample file as its incomplete and being exctracted|downloaded from network interface '''
            SKIP = 1
        else:
            ''' No need to skip the sample, sample file is complete and can be used for submission '''
            SKIP = 0

        return(SKIP)

''' Function to update the file submitted counter '''
def updateCounterFile(latest_file_counter):
    global COUNTER_FILE
    fc = open(COUNTER_FILE, 'a')
    try:
        fc.write("Time:%s\tSamples/Hr:%s\n" % (strftime("%Y-%m-%d %H:%M:%S", localtime()),str(latest_file_counter)))
    except Exception as e:
        logger.info ( "%s" % type(e))
        print type(e)
        print str(e)
        logger.info ("%s" % str(e))
        return(1)

    fc.close()

    logger.info("File counter updated is : %d " % (latest_file_counter))
    global file_counter
    file_counter = 0

    return(0)

 
''' Increament the counter '''
def increament():
    global file_counter
    file_counter += 1
    return(file_counter)
    #updateCounterFile(file_counter)
        

''' Function to send the heartbeat so that to have sesson alive '''
def heartbeat(matdip, sesuser_enc):

    global HEARTBEAT_MISSED

    headers = {'Accept': 'application/vnd.ve.v1.0+json','Content-Type': 'application/json','VE-SDK-API': sesuser_enc}
    logger.info ("Headers for heartbeat : %s" % (headers))

    # Extracting the Session ID
    url = "https://"+ matdip + "/php/"+ "heartbeat.php"

    try:
        rest_req = requests.get(url, headers=headers,verify=False)
    except requests.exceptions.Timeout:
        # Maybe set up for a retry, or continue in a retry loop
        HEARTBEAT_MISSED = HEARTBEAT_MISSED + 1
        logger.error("Connection timed out! Failed to establish a connection!")
        logger.error("Retrying...!")
        logger.error("Failed to send heartbeat to keep session alive. Please check the BRO-ATD configuration.")
        logger.error("User may have to restart the atdsubmitter daemon.")
        return
    except requests.exceptions.TooManyRedirects:
        # Tell the user their URL was bad and try a different one
        HEARTBEAT_MISSED = HEARTBEAT_MISSED + 1
        logger.error("Too many redirects! Failed to establish a connection!")
        logger.error("Failed to send heartbeat to keep session alive. Please check the BRO-ATD configuration.")
        logger.error("User may have to restart the atdsubmitter daemon.")
        return
    except requests.exceptions.RequestException as e:
        # catastrophic error. bail.
        HEARTBEAT_MISSED = HEARTBEAT_MISSED + 1
        logger.error("Failed to establish a connection!")
        print "\nERROR : Failed to establish a connection! No route to host[%s].\n" % (matdip)
        logger.error("Failed to send heartbeat to keep session alive. Please check the BRO-ATD configuration.")
        logger.error("User may have to restart the atdsubmitter daemon.")
        logger.error("%s" % (e))
        return

    HEARTBEAT_MISSED = 0

    # Create the Response dictionary
    rest_response_dict = {}
    rest_request = rest_req.text.replace('true','"true"').replace('false','"false"')
    rest_response_dict = eval(rest_request)

    print "Response for heartbeat : "
    for k, v in rest_response_dict.items():
        print(k, v)

    user_id = rest_response_dict['results']['userId']
    session = rest_response_dict['results']['session']

    print "heartbeat session result : %s" % (session)

    # Base 64 encode of username:password
    logger.info('Heartbeat received.')
 

'''
Function to create login session
Args:
	matdip 		: ATD device IP
	username 	: ATD device UI Username
	password	: ATD device UI Pasword
'''
def encode_login(matdip,username,password):
    global sesuser_enc
    logger.info("Creating login session to MATD : %s with User: %s" % (matdip,username))

    # Base 64 encode of username:password
    userpass = username + ':' + password
    userpass_enc = base64.b64encode(userpass)

    # Creating the HTTP headers
    headers = {'Accept': 'application/vnd.ve.v1.0+json','Content-Type': 'application/json','VE-SDK-API': userpass_enc}
    #logger.info ("Headers for enocde login : %s" % (headers))

    # Extracting the Session ID
    url = "https://"+ matdip + "/php/"+ "session.php"
    #rest_req = requests.get(url, headers=headers,verify=False)
    try:
        rest_req = requests.get(url, headers=headers,verify=False)
    except requests.exceptions.Timeout:
        # Maybe set up for a retry, or continue in a retry loop
        logger.error("Connection timed out! Failed to establish a connection!")
        logger.error("Retrying...!")
    except requests.exceptions.TooManyRedirects:
        # Tell the user their URL was bad and try a different one
        logger.error("Too many redirects! Failed to establish a connection!")
    except requests.exceptions.RequestException as e:
        # catastrophic error. bail.
        logger.error("Failed to establish a connection!")
        print "\nERROR : Failed to establish a connection! No route to host[%s].\n" % (matdip)
        logger.error("%s" % (e))
        #rest_req = "retry"
        #sesuser_enc = ""
        sys.exit(1)
        #return(rest_req,sesuser_enc)

    # Create the Response dictionary
    rest_response_dict = {}
    rest_request = rest_req.text.replace('true','"true"').replace('false','"false"')
    rest_response_dict = eval(rest_request)

    isLoginSuccessful = rest_response_dict['success']

    if isLoginSuccessful == "false":
        errorMessage = rest_response_dict['errorMessage']
        print "\nerrorMessage : ", errorMessage
        sys.exit(1)

    # Extract the Session ID and User ID
    session_id = rest_response_dict['results']['session']
    user_id = rest_response_dict['results']['userId']

    # Base 64 encode of username:password
    sesuser = session_id + ':' + user_id
    sesuser_enc = base64.b64encode(sesuser)
    #logger.info ("sesuser_enc : %s" % (sesuser_enc))
    logger.info('session created')

    return(rest_req,sesuser_enc)


''' 
Function to create the Response dictionary
''' 
def dict_create(rest_req):
    rest_response_dict = {}
    rest_request = rest_req.text.replace('true','"true"').replace('false','"false"').replace('null','"null"')
    rest_response_dict = eval(rest_request)
    return(rest_response_dict)


''' 
    function to move the files to user defined directory on successful submission 
'''
def move(src, dst):
    global DISK_FREE_SPACE_CHECK_FLAG

    if DISK_FREE_SPACE_CHECK_FLAG == True:
        logger.error("File system size is critically low. Failed to move the sample")
        logger.info ("Please do the disk cleanup to avoid failures.")
        return

    logger.info("Moving Files : SRC[%s] -> DST[%s]" % (src, dst))
    base_name = os.path.basename(src)
    CMD = "mv -f " + src + " " + dst + "/" + base_name
    DST = dst + "/" + base_name
    ret = 0
    #os.system (CMD)
    #shutil.move(src,dst)
    os.rename(src, DST)

def md5Checksum(filename):
    with open(filename, 'rb') as fh:
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()

'''
    Function to upload the file 
'''
def File_Upload(matdip, sesuser_enc, file_name, analyzer_profile_id, BroVersion, silent_mode):
    global LOCAL_SCAN_DIRECTORY_INTERVAL
    LOCAL_SCAN_DIRECTORY_INTERVAL = 0

    global DIR_SCAN_RUN_FLAG

    global submission_time

    # Create the HTTP Session and send GET Request
    File_MD5 = ""
    statinfo = ""

    try:
        statinfo = os.stat(file_name)
    except IOError as e:
        logger.error("Failed stat file. Error [%s]" % (e))
    
    SAMPLE_CHECK_PASS = True

    ''' creating hashTable object to access class methods '''
    obj_hash = hashTable()

    ''' md5value = hashlib.md5(file_name).hexdigest()'''
    md5value = md5Checksum(file_name)

    isHashFound = obj_hash.searchHash(md5value)
    if isHashFound == True:
        logger.info("Skipping re-analysis of sample [%s]." % (file_name))

    if os.path.exists(PRINT_HASH_FLAG):
        logger.info("Printing hash table.")
        obj_hash.printHashTable()

    ''' creating rest_Utils class object to access methods '''
    obj_rest = rest_Utils()

    if isHashFound == False and silent_mode == "OFF":

        File_MD5 = ""
    
        fileSizes = [0,0]
    
        fileMimeType = magic.from_file(file_name, mime=True)
    
        '''
            get min and max file size allowed for ADT submission for supported file types
        '''
        isFileAllowed = obj_rest.getMinMaxFileSize(matdip, fileMimeType, "", fileSizes)
    
        if isFileAllowed == 3:
            DIR_SCAN_RUN_FLAG = False
            return
        else:
            submission_time = time.time()

        if isFileAllowed == 0:
            SAMPLE_CHECK_PASS = False   

        if isFileAllowed == 1:
            actualFileSize = statinfo.st_size
        
            #logger.info("Min File Size :[%d] Max File Size :[%d]" % (fileSizes[0], fileSizes[1]))
            logger.info("File Type :[%s] Min File Size :[%s] Max File Size :[%s] Actual Size :[%s]" % (fileMimeType, fileSizes[0], fileSizes[1], statinfo.st_size))
        
            print "actualFileSize : [%s] fileSizes[%s]" % (actualFileSize, fileSizes[0])
        
            '''
                Check if file size is below minimum allowed size
            '''
            if (int(actualFileSize) < int(fileSizes[0])):
                logger.info("File is unsupported. Below minimum size.")
                SAMPLE_CHECK_PASS = False
        
            '''
                Check if file size is exceeding maximum allowed size
            '''
            if (int(actualFileSize) > int(fileSizes[1])):
                logger.info("File is unsupported. File size exceeding maximum allowed file size.")
                SAMPLE_CHECK_PASS = False
    else:
        SAMPLE_CHECK_PASS = False

    if (SAMPLE_CHECK_PASS == True) and (silent_mode == "OFF"):
    #if False:
        try:
            
            print "we are doing new REST API."
            # analyzer_profile_id = "1"
            # Preparing URL for REST submission 
            url = "https://"+ matdip + "/php/" + "atdHashLookup.php"
            print "URL:",url
            '''
            Note : Bro Version is not used any more.
            BroVersion = "1.7"
            BroVersion = BroVersion.replace(".", "_")
            '''
    
            ''' 
            messageId : "99bb88rr11oo00" is a constant string used to define type of submission 
            # Note : do not change the string i.e. messageId 
            '''
            headers = {'Accept': 'application/vnd.ve.v1.0+json','VE-SDK-API': sesuser_enc}
            print "input headers  =  ",headers
   
            #postdata = {'{"md5":\"'+str(md5value)+'\"}'}
            postdata = {'data':'{"md5":\"'+str(md5value)+'\"}'}
            print "input data  =  ",postdata
   
            upload_rest_req = "" 
            #upload_rest_req = requests.post(url,postdata,headers=headers,verify=False)
            upload_rest_req = requests.post(url,postdata,headers=headers,verify=False)
    
            MD5 = string.upper(md5value)

            response = upload_rest_req.json()

            searchResult = response['results'][MD5]

            if searchResult != '0':
                logger.error("Sample will not be submitted to ATD for analysis.")
                logger.error("Sample is already submitted to ATD. You can view the results on ATD [%s]." % (matdip))
                SAMPLE_CHECK_PASS = False

        except:
            logger.error("Failed to Submit Sample : [%s]." % (file_name))
            logger.info("Please check REST daemon configuration for ATD. Check if ATD device is UP and Running.")
            return False


    if (SAMPLE_CHECK_PASS == True) and (silent_mode == "OFF"): 
        try:
            # analyzer_profile_id = "1"
            # Preparing URL for REST submission 
            url = "https://"+ matdip + "/php/" + "fileupload.php"
            '''
            Note : Bro Version is not used any more.
            BroVersion = "1.7"
            BroVersion = BroVersion.replace(".", "_")
            '''
    
            ''' 
            messageId : "99bb88rr11oo00" is a constant string used to define type of submission 
            # Note : do not change the string i.e. messageId 
            '''
            messageId = "99bb88rr11oo00"
    
            headers = {'Accept': 'application/vnd.ve.v1.0+json','VE-SDK-API': sesuser_enc}
            print "input headers  =  ",headers
   
            source_IP = ""
 
            postdata = {'data':'{"data":{"xMode":0,"skipTaskId":1, "srcIp":\"'+str(source_IP)+'\","destIp":"","messageId":\"'+str(messageId)+'\","analyzeAgain":1,"vmProfileList":'+str(analyzer_profile_id)+'},"filePriorityQ":"run_now"}'}
            print "input data  =  ",postdata

            #file_up = {'amas_filename': open(file_name, 'rb')}
            file_data_up = open(file_name, 'rb').read()
            #file_up = {'amas filename': [os.path.basename(file_name).decode("utf-8").encode("ascii","ignore"), file_data_up]}
            file_up = {'amas filename': [unicode(os.path.basename(file_name), errors='ignore'), file_data_up]}

            try:
                upload_rest_req = requests.post(url,postdata,files=file_up,headers=headers,verify=False)
            except Exception as e:
                raise Exception(e)
            else:
                task_id='task_id = '+str(upload_rest_req.text)
                json = upload_rest_req.json()
                print "task id  =  ",json['results'][0]['taskId']
    
                File_MD5 = json['results'][0]['md5']
    
                if silent_mode == "ON":
                    logger.info("REST daemon mode : [Silent Mode] - Submission of file : [%s] SUCCESS." % (file_name))
                else:
                    logger.info("REST daemon mode : [Active Mode] - Submission of file : [%s] SUCCESS." % (file_name))

        except:
            logger.error("Upload : Failed to Submit Sample : [%s]." % (file_name))
            logger.info("Please check REST daemon configuration for ATD. Check if ATD device is UP and Running.")
            return False

    increament()

    SAMPLE_SUBMISSION_FLAG = True

    logger.info("File's submitted : %d " % (file_counter))

    if isHashFound == False:
        obj_hash.update_hash(md5value)
        logger.info("Hash [%s] for sample [%s] is updated." % (md5value, file_name))

    File_MD5 = md5Checksum(file_name)

    logger.info ("File \t\t: [%s] \n\t\t\tMD5 \t\t\t: [%s] \n\t\t\tfile-size \t\t: [%s] \n\t\t\tfile-type \t\t: [%s] \n\t\t\tsubmission-time \t: [%s] " % (file_name, File_MD5.upper(), statinfo.st_size, magic.from_file(file_name, mime=True), strftime("%Y-%m-%d %H:%M:%S", localtime())))

    global FILE_REMOVE_FLAG

    if FILE_REMOVE_FLAG == "YES":
        try:
            os.remove(file_name) if os.path.exists(file_name) else None
        except:
            logger.error("Failed to remove file : [%s] after submission." % file_name)
    else:
        global file_move_path
        logger.info("Before moving / removing the file. file_move_path : %s" % file_move_path)
        try:
            move(file_name, file_move_path)
        except:
            logger.error("Failed to move file : [%s] to %s path after submission." % (file_name, file_move_path))
            logger.info("Stopping REST Submission.")
            logger.info("About to remove the pid file path.")
            #TEST THIS#
            finish(PID_FILE)
        else:
            logger.info("File moved successfully.")
    print "returning from File Upload."


'''
    Function    : logout
    Description : logout function will logout from ATD UI session.
'''
def logout (matdip,sesuser_enc):
    # Create the HTTP Session and send GET Request

    global LOGOUT_RESULT
    LOGOUT_RESULT = 0

    url = "https://"+ matdip + "/php/" + "session.php"
    headers = {'Accept': 'application/vnd.ve.v1.0+json','Content-Type': 'application/json','VE-SDK-API': sesuser_enc}
    try:
        del_rest_req = requests.delete(url, headers=headers,verify=False)
    except requests.exceptions.Timeout:
        # Maybe set up for a retry, or continue in a retry loop
        logger.error("Connection timed out! Failed to establish a connection!")
        logger.error("Retrying...!")
        LOGOUT_RESULT = 1
    except requests.exceptions.TooManyRedirects:
        # Tell the user their URL was bad and try a different one
        logger.error("Too many redirects! Failed to establish a connection!")
        LOGOUT_RESULT = 1
    except requests.exceptions.RequestException as e:
        # catastrophic error. bail.
        logger.error("Failed to establish a connection!")
        print "\nERROR : Failed to establish a connection! No route to host[%s].\n" % (matdip)
        logger.error("%s" % (e))
        LOGOUT_RESULT = 1
        #rest_req = "retry"
        #sesuser_enc = ""
        #sys.exit(1)


    # Create the Response dictionary
    del_response_dict = dict_create(del_rest_req)

    # Test Condition for PASS/FAIL
    if  del_rest_req.status_code == 200 and del_response_dict['success'] == 'true':
        logger.info("- Delete Session Successful.")
        print "\n\nPASS :  - Delete Session\n"
    else:
        logger.error("- Delete Session Failed.")
        print "\n\nFAIL :  - Delete Session\n"

'''
    Finish function is used to stop|shutdown the daemon.
'''
def finish(pidfile):
    """
       Stop the daemon
    """
    global SILENT_MODE

    # Get the pid from the pidfile
    #logger.info("Got PID file to stop REST daemon. [%s]" % (pidfile))
    try:
        pf = file(pidfile, 'r')
        pid = int(pf.read().strip())
        pf.close()
        try:
            os.kill(pid, 0)
        except OSError:
            os.remove(self.pidfile)
            pid = None
    except IOError:
        pid = None

    #logger.info("PID : [%d]" % pid)

    if not pid:
        message = "pidfile %s does not exist. Daemon not running?\n"
        sys.stderr.write(message % pidfile)
        return  # not an error in a restart

    if SILENT_MODE != 1:
        global loginInfo
        sesuser_enc = loginInfo['sesuser_enc']
        global ATDInfo
        matdip = ATDInfo['matdip']

    # Try killing the daemon process
    try:
        if SILENT_MODE != 1:
            logout(matdip, sesuser_enc)
        logger.info("Shutting down the daemon.")
        if os.path.exists(pidfile):
            os.remove(pidfile)

        while 1:
            os.kill(pid, SIGTERM)
            time.sleep(0.1)
    except OSError, err:
        logger.info("Caught an exception. Failed to Shutdown the daemon.")
        err = str(err)
        if err.find("No such process") > 0:
            if os.path.exists(pidfile):
                os.remove(pidfile)
        else:
            print str(err)
            sys.exit(1)

'''
   function to get the per hour average of samples submitted for analysis
'''
def get_average_samples_hr():
    global COUNTER_FILE
    
    count = 0

    if not os.path.exists(COUNTER_FILE):
        print "Can not get the statistics. File [%s] does not exist." % (COUNTER_FILE)

    totalSampleCount = 0
    fin = open(COUNTER_FILE, 'r')
    for line in fin:
        if "Samples/Hr" in line:
            fields = line.strip().split(':')
            #print(fields[4])
            count += 1
            totalSampleCount += int(fields[4])

    #logger.info("Number of entries found in counter file : [%d]" % (count))
    print "Total samples submitted [%d] in [%d] hour's" % (totalSampleCount,count)

    if count == 0:
        totalSampleCount = 0
        return(totalSampleCount)

    totalSampleCount = (totalSampleCount / count)
    fin.close()

    return(totalSampleCount)

    
'''
   Function to update the file header which tells start time of script and the number of files resides in bro sample extraction directory.
'''
def update_file_header():
    global COUNTER_FILE
    global SILENT_MODE

    fp = open(COUNTER_FILE, 'w')

    global SCRIPT_START_TIME
    global old_files_count_atStart

    '''
        Rest Submission Daemon
    '''
    fp.write("McAfee Advance Threat Defense - Bro Submitter Version : %s\nStart Time [%s] : [%s]\nNumber of samples in sample's directory @ [%s] : %d\n\n" % ("Active Mode" if SILENT_MODE==0 else "Silent Mode", VERSION, SCRIPT_START_TIME, SCRIPT_START_TIME, old_files_count_atStart))

    fp.close()

def print_dict():
    global loginInfo
    sesuser_enc = loginInfo['sesuser_enc']
    global ATDInfo
    matdip = ATDInfo['matdip']
    for key,value in ATDInfo.iteritems():
            logger.info( "In print_dict >>>> KEY : [%s] VALUE : [%s]" % (key,value))

'''
    CLASS : hashTable
    Desc  : class holds the samples hash entries to be submitted to ATD for analysis. 
'''
class hashTable():
    ''' hashTable is a class with methods to store the last MAX_INDEX has entries of samples extracted and being submitted to ATD '''

    global hashmap

    global HASH_INDEX

    ''' Initialization '''
    def __init__(self):
        hashmap = [None] * MAX_INDEX

    ''' update md5 hash to the table '''
    def update_hash(self, md5value):
        global HASH_INDEX

        if HASH_INDEX < MAX_INDEX-1:
            HASH_INDEX = HASH_INDEX + 1
            print "INDEX:", HASH_INDEX
            hashmap[HASH_INDEX] = md5value
        else:
            HASH_INDEX = 1
            hashmap[HASH_INDEX] = md5value

    '''
        search file hash in hash table
        return True if found
        else return false
    '''
    def searchHash(self, md5value):
        for i in range(1,MAX_INDEX):
            if hashmap[i] == md5value:
                print "\nFound [%s] at index [%d]\n" % (md5value, i)
                return True
        return False

    ''' print complete hash table '''
    def printHashTable(self):
        for i in range(1,MAX_INDEX):
            logger.info("Index : [%d] Sample Hash : [%s]" % (i, hashmap[i]))


class rest_Utils():

    def __init__(self):
        print "Initializing restUtils object."
 
    '''
        Function    : sample_submission_from_dir_scan
        Description : to check if sample extraction directory provided by customer / user is not empty.
                      If directory is not empty and has some samples in it, pick the samples and submit them for analysis to Advance Threat Defence device.
                      On submission samples will be deletes or will be moved to directory as per customers choice.
    '''
    def sample_submission_from_dir_scan(self, matdip, sesuser_enc, analyzer_profile_id, bro_version, scan_dir_path, silent_mode, filenames):

        global DIR_SCAN_RUN_FLAG

        for newfile in filenames:
            logger.info("filename : [%s] scan_dir_path : [%s]" % (newfile,scan_dir_path))
            submission_file_path = scan_dir_path + "/" + newfile
 
            SKIP_SUBMISSION = isFileExctractionCompleted(submission_file_path)
 
            if SKIP_SUBMISSION == 1:
                logger.error("Skipping file[%s] submission for now. File is being modified." % (newfile))
                continue
 
            statinfo = os.stat(submission_file_path)
            #FILE_UPLOAD_FLAG = self.check_file_size(statinfo.st_size)
            FILE_UPLOAD_FLAG = True
 
            if FILE_UPLOAD_FLAG == True:
                logger.info("On directory[%s] scan -> file for submission is : [%s]" % (scan_dir_path, submission_file_path))
 
                ''' adding sleep/delay between sample submission from scanning directory '''
                time.sleep(1)
 
                returnCode = File_Upload(matdip, sesuser_enc, submission_file_path, analyzer_profile_id, ATDInfo['bro_version'], silent_mode)
                if returnCode == False:
                    break
            else:
                logger.error("File size is greater than 120 Mb. Failed to submit the file to ATD for analysis.")
 
        DIR_SCAN_RUN_FLAG = False
        return(True)

    '''
        Function    : scan_dir_for_samples
        Description : If directory is not empty and has some samples in it, pick the samples and submit them for analysis to Advance Threat Defence device.
    '''
    def scan_dir_for_samples(self, matdip, sesuser_enc, analyzer_profile_id, bro_version, scan_dir_path, silent_mode):

        global DIR_SCAN_RUN_FLAG

        if not os.listdir(scan_dir_path):
            ''' scan dir is empty returning. No need to scan for samples. '''
            return(True)

        if DIR_SCAN_RUN_FLAG == True:
            return (True)

        DIR_SCAN_RUN_FLAG = True

        '''
        print "matdip[%s], sesuser_enc[%s], analyzer_profile_id[%s], bro_version[%s], scan_dir_path[%s], silent_mode[%s]" % (matdip, sesuser_enc, analyzer_profile_id, bro_version, scan_dir_path, silent_mode)
        '''
        for (dirpath, dirnames, filenames) in walk(scan_dir_path):
            break

        try:
            thread.start_new_thread (self.sample_submission_from_dir_scan, (matdip, sesuser_enc, analyzer_profile_id, bro_version, scan_dir_path, silent_mode,filenames))
        except Exception as e:
            DIR_SCAN_RUN_FLAG = False
            logger.error("Error: Unable to start thread for sample submission from directory:[%s] scan. Error:[%s]" % (scan_dir_path, e))

        return(True)

    '''
        function to get the free space for disk where filesystem is mounted.
    '''
    def getFilesystemSize(self, scan_dir):
        if not os.path.exists(scan_dir):
            logger.error("Failed to find Bro sample path : [%s], Shutting down the REST submitter daemon." % (scan_dir))
            
        statvfs = os.statvfs(scan_dir)

        statvfs.f_frsize * statvfs.f_blocks     # Size of filesystem in bytes
        statvfs.f_frsize * statvfs.f_bfree      # Actual number of free bytes

        return ((statvfs.f_frsize * statvfs.f_bfree)/(1024*1024))


    '''
        get min and max file size allowed for ADT submission for supported file types
    '''
    def getMinMaxFileSize(self, matdip, fileType, fileExt, fileSizes):

        url = "https://" + matdip + "/php/ATDCustomValidator.php?command=getMinMaxSize&fileType=" + fileType + "&fileExtn=" + fileExt
        
        print "url : ", url
        
        context = ssl._create_unverified_context()
        
        try:
            result = urllib2.urlopen(url, context=context)
        except urllib2.HTTPError, e:
            logger.error("getFileSize : HTTPError = %s" % (str(e.code)))
            time.sleep(180)
            return 3
        except urllib2.URLError, e:
            logger.error("getFileSize : URLError = %s" % (str(e.reason)))
            time.sleep(180)
            return 3
        except httplib.HTTPException, e:
            logger.error("getFileSize : HTTPException")
            time.sleep(180)
            return 3
        except Exception:
            import traceback
            logger.error("getFileSize : generic exception: %s" % (traceback.format_exc()))
            # catastrophic error. bail.
            logger.error("getFileSize : Failed to establish a connection! No route to host[%s].\n" % (matdip))
            print "\nERROR : getFileSize : Failed to establish a connection! No route to host[%s].\n" % (matdip)
            time.sleep(180)
            return 3
        
        result = result.read()
        
        jsonObj = json.loads(result)
        
        fileSizes[0] = jsonObj['allowedMin']
        
        fileSizes[1] = jsonObj['allowedMax']

        isFileTypeAllowed = jsonObj['sampleFileCheck']
        if isFileTypeAllowed == 0:
            logger.error("File Type [%s] is not allowed by ATD. Sample will not be submitted to ATD for analysis." % (fileType))
            return False
        
        logger.info("File Sizes result : [%s]" % (result))

        return True


        ''' Function to read the config change '''
    def read_conf_change(thread_name):
        logger.info("We are in thread : %s." % (thread_name))
        global continue_flag
        while (continue_flag == True):
            logger.info("We are in thread : %s." % (thread_name))
            time.sleep(1)
        logger.info("continue_flag is now %s " % continue_flag)
    
    
    ''' Function to monitor the config change '''
    def monitor_config_change():
       try:
           logger.info ("about to spawn a thread for monitoring config change.");
           thread.start_new_thread( read_conf_change, ("thread - 1",))
       except:
           logger.error("Error: unable to start thread")
 
 
# Class to define the REST deamon members and method #
class Daemon():
    """
        A generic daemon class.
       
        Usage: subclass the Daemon class and override the run() method
        """

    path = ""

    global matdip
    global username
    global password
    global analyzer_profile_id
    global bro_sample_path
    global bro_version
    global silent_mode
    global env_path

    sesuser_enc = ''
    file_move_path = ''
    FILE_REMOVE_FLAG = "NO"

    def __init__(self,
                 pidfile,
                 stdin='/dev/null',
                 stdout='/dev/null',
                 stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile

    def daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            logger.error("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # decouple from parent environment
        # os.chdir("/")
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            logger.error("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        file(self.pidfile, 'w+').write("%s\n" % pid)

    def delpid(self):
        os.remove(self.pidfile)

    '''
        This function will receive the signal sent by REST script to running daemon to stop the process.
        On signal receiver receive_signal will call the finish function to stop the daemon.
    '''
    def receive_signal(self, signum, stack):
        if signum == signal.SIGINT:
            print("\nReceived keyboard interrupt. Exiting...")
            sys.exit(1)
        #logger.info("Got signal SIGUSR1 to stop the rest submission daemon.")
        finish(self.pidfile)
    
    def start(self):
        """
            Start the daemon
        """
        global COUNTER_FILE
       
        global SILENT_MODE

        global submission_time
        submission_time = time.time()

        global SCRIPT_START_TIME

        global last_file_counter_update_time 
        last_file_counter_update_time = time.time()

        ''' Registering signal SIGUSR1 for handling process shutdown '''
        signal.signal(signal.SIGUSR1, self.receive_signal)
        signal.signal(signal.SIGINT, self.receive_signal)

        global continue_flag
        continue_flag = True

        ''' Check for a pidfile to see if the daemon already runs '''
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
            try:
                os.kill(pid, 0)
            except OSError:
                os.remove(self.pidfile)
                pid = ""
        except IOError:
            pid = None

        if pid:
            #logger.info("PID file exists. Daemon is already running.")
            message = "pidfile %s already exist. Daemon already running?\n"
            sys.stderr.write(message % self.pidfile)
            sys.exit(1)

        config = ConfigParser.ConfigParser()
        try:
            config.readfp(open(BRO_CONF_FILE))
        except IOError:
            print "\nError : Please do configure before starting the REST Submission.\n"
            sys.exit(1)

        '''
            Setting up logger (logging mechanism) for REST submission daemon.
        '''
        if not ('restart' == sys.argv[1]):
            log_setup()

        self.silent_mode = config.get('BRO CONFIG', 'Silent Mode')

        '''
            If silent mode is ON,
            No need to get details from user like Username / Matdip / Password / Analyzer Profile Id.
        '''
        if self.silent_mode == "OFF":
            self.matdip = config.get('BRO CONFIG', 'matdip')
            self.username = config.get('BRO CONFIG', 'username')
            self.password = getpass.getpass("\nPlease provide the password for user [%s] : " % (self.username))
            self.analyzer_profile_id = config.get('BRO CONFIG', 'Analyzer profile id')

            SILENT_MODE = 0
        else:
            SILENT_MODE = 1

        ''' 
            Path where samples are places or extracted from network interface 
        '''
        self.bro_sample_path = config.get('BRO CONFIG', 'Bro sample path')
        if (self.bro_sample_path) and (not os.path.exists(self.bro_sample_path)):
            os.makedirs(self.bro_sample_path)

        self.file_remove = config.get('BRO CONFIG', 'Remove file on submission')
        global file_move_path
        global FILE_REMOVE_FLAG

        logger.info("Starting REST Submission daemon.")
        logger.info("REST Daemon Version : %s" % (VERSION))

        flag_value = self.file_remove

        if flag_value == "NO":
            FILE_REMOVE_FLAG = "NO"
            file_move_path = config.get('BRO CONFIG', 'Directory to move files')
            if file_move_path == "":
                file_move_path = SAMPLE_BACKUP_DIR
                if not os.path.exists(file_move_path):
                    os.makedirs(file_move_path)
        else:
            FILE_REMOVE_FLAG = "YES"
            logger.info("@@@@@@ Config read ::::: FILE_REMOVE_FLAG : %s" % FILE_REMOVE_FLAG)
        '''
            Installation Path:
            This is the path where all the files of REST daemon like log files, counter files etc.
            will be stored in this path.
        '''
        self.env_path = config.get('BRO CONFIG', 'Installation path')

        if self.silent_mode == "OFF":
            if self.matdip == "" or self.username == "" or self.password == "" or self.bro_sample_path == "" :
                exit(1);
        elif self.silent_mode == "ON" and self.bro_sample_path == "":
            exit(1);
 
        global ATDInfo 

        ATDInfo['matdip'] = self.matdip
        ATDInfo['username'] = self.username
        ATDInfo['silent_mode'] = self.silent_mode
        ATDInfo['analyzer_profile_id'] = self.analyzer_profile_id
        ATDInfo['bro_sample_path'] = self.bro_sample_path
        ATDInfo['remove_file_on_submission'] = self.file_remove
        ATDInfo['bro_version'] = 1.7 #self.Bro_Version 
        ATDInfo['env_path'] = self.env_path

        '''
        for key,value in ATDInfo.iteritems():
            logger.info( "Login : KEY : [%s] VALUE : [%s]" % (key,value))
        '''

        if self.silent_mode == "OFF":
            logger.info("<<<<<<<<<<< Doing login >>>>>>>>>>>>>")
            rest_req = ""
            if self.username and self.password and self.matdip and self.analyzer_profile_id:
                rest_req, self.sesuser_enc = encode_login(self.matdip, self.username, self.password)

            global loginInfo
            loginInfo['rest_req'] = rest_req
            loginInfo['sesuser_enc'] = self.sesuser_enc

            #logger.info("login info : loginInfo[rest_req] : %s, ginInfo[sesuser_enc] : %s" % (loginInfo['rest_req'], loginInfo['sesuser_enc']))

        path, dirs, files = os.walk(self.bro_sample_path).next()
        global old_files_count_atStart
        old_files_count_atStart = len(files)
        # Recording daemon start time #
        SCRIPT_START_TIME = strftime("%Y-%m-%d %H:%M:%S", localtime())
        #Function to update the file header which tells start time of script and the number of files resides in bro sample extraction directory.#
        update_file_header()

        '''
        fp = open(counter_file_name, 'w')
        path, dirs, files = os.walk(self.bro_sample_path).next()
        files_count = len(files)
        fp.write("Script Start Time: [%s]\nNumber of samples in Bro directory @ [%s] : %d\n\n" % (strftime("%Y-%m-%d %H:%M:%S", localtime()), strftime("%Y-%m-%d %H:%M:%S", localtime()),files_count))
        fp.close()
        '''

        ''' Start the daemon '''
        self.daemonize()
        ''' Calling run method '''
        self.run_rest()

    '''
        Function    : show_configuration
        Description : This function will show the saved configuration provided by user.
    '''
    def show_configuration(self):
        logger.info('Starting REST submission with below configuration:')
        print "matdip : {0}".format(self.matdip)
        logger.info('matdip : %s' % (self.matdip))
        print "username : {0}".format(self.username)
        logger.info('username : %s' % (self.username))
        print "password : {0}".format(self.password)
        print "Silent Mode : {0}".format(self.silent_mode)
        print "analyzer_profile_id : {0}".format(self.analyzer_profile_id)
        logger.info('analyzer_profile_id : %s' % (self.analyzer_profile_id))
        print "Bro sample path : {0}".format(self.bro_sample_path)
        logger.info('Bro sample path : %s' % (self.bro_sample_path))


    '''
        Function    : stop
        Description : This function will stop the daemon.
    '''
    def stop(self):
        try:
            log_setup()
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None
        else:
            #logger.info("My PID : [%d] about to send sigusr1 signal to PID : [%d]" % (os.getpid(), pid))
            try:
                os.kill(pid, 0)
            except OSError:
                logger.info("REST daemon is not Running.")
                try:
                    if os.path.exists(self.pidfile):
                        os.remove(self.pidfile)
                except IOError:
                    logger.error("Failed to remove the PID file. Try removing manually. PID File : [%s]" % (self.pidfile))
            else:
                os.kill(pid, signal.SIGUSR1)
                logger.info("Adding 5 sec delay to clear the signal processing.")
                time.sleep(5)       
            '''
            try:
                os.kill(pid, 0)
            except OSError:
                logger.info("About to remove the pid file path.")
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                logger.error("PID still exist. Failed to remove PID file.")
            '''


    '''
        Function    : restart
        Description : This function will restart the daemon with user provided (stored in configuration file) configuration.
    '''
    def restart(self):
        """
            Restart the daemon
        """
        global LOGOUT_RESULT
        
        pid = None

        self.stop()

        while True:
            try:
                pf = file(self.pidfile, 'r')
                pid = int(pf.read().strip())
                pf.close()
                if LOGOUT_RESULT == 1:
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        os.remove(self.pidfile)
                        pid = None
            except IOError:
                pid = None

            time.sleep(1)

            if pid == None:
                break

        self.start()


    '''
        Function    : status
        Description : This function will show the daemon status (Running | Stopped).
    '''
    def status(self):
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
            try:
                os.kill(pid, 0)
            except OSError:
                os.remove(self.pidfile)
                pid = ""
        except IOError:
            pid = None

        if pid:
            message = "REST Submission daemon is " + '\033[93m' + "Running" + '\033[0m' + "."
        else:
            message = "REST Submission daemon is " + '\033[93m' + "Stopped" + '\033[0m' + "."
        print "\nSTATUS : \"%s\"\n" % (message)
        sys.exit(0)

    '''
        Function    : stats
        Description : This function will display the statistics of REST submission.
                      Will display the file counter and the average per hour samples.
    '''
    def stats(self):

        global COUNTER_FILE
        signal.signal(signal.SIGINT, self.receive_signal)
        
        try:
            with open(COUNTER_FILE, 'r') as fin:
                print fin.read()
        except IOError:
             print "No sample submission data available to process. NO stats available "
             sys.exit(1)
        totalSampleCount = get_average_samples_hr()

        print "_____________________________________\n"
        print "Average Sample's / Hour    =\t%d" % (totalSampleCount)
        print "_____________________________________\n"

        fin.close()

        config = ConfigParser.ConfigParser()
        config.readfp(open(BRO_CONF_FILE))
        self.bro_sample_path = config.get('BRO CONFIG', 'Bro sample path')

        print "Number of samples in Bro directory @ [%s] : %d\n\n" % (strftime("%Y-%m-%d %H:%M:%S", localtime()), len(os.walk(self.bro_sample_path).next()[2]))

    '''
    Function    : configure
    Description : This is the function which will accept the configuration from customer / user.
                  Accepted configuration will be saved to REST submission configuration file.
                  At end on user input / choice daemon will be started with latest configuration.
    '''
    def configure(self):
        SAMPLE_PARENT_DIR = ""
        yes = set(['yes', 'y', 'ye'])
        no = set(['no', 'n'])

        signal.signal(signal.SIGINT, self.receive_signal)

        self.silent_mode = raw_input('\033[92m' + "\nRun in Silent mode? [y/n] : [n]\t\t\t: " + '\033[0m')
    
        global SILENT_MODE
        if self.silent_mode in yes:
            SILENT_MODE = 1
            print "Note: Silent Mode Enabled!"
        else:
            SILENT_MODE = 0
            print "Note: Active Mode Enabled!"

        if SILENT_MODE == 0:
            while self.matdip == "":
                self.matdip = raw_input('\033[92m' + "Enter MATD IP \t\t\t\t\t: " + '\033[0m')
                if self.matdip == "":
                    print "Invalid MATD IP Address. Please try again."
                else:
                    try:
                        socket.inet_aton(self.matdip)
                    except IOError:
                        print "Error \t: Not a valid IP address.\n\t: Please enter a valid IP Address."
                        sys.exit(1)

            while self.username == "":
                self.username = raw_input('\033[92m' + "Enter Username \t\t\t\t\t: " + '\033[0m')
                if self.username == "":
                    print "Invalid MATD Username. Please try again."
            self.analyzer_profile_id = raw_input('\033[92m' + "Enter Analyzer Profile Id " + '\033[0m' + "[default:' ']" + '\033[92m' + "\t\t: " + '\033[0m')
            if self.analyzer_profile_id == "":
                print "Note : Default Analyzer profile will be used for sample Analysis."
                self.analyzer_profile_id = "0"
            else:
                try:
                    val = int(self.analyzer_profile_id)
                except ValueError:
                    print("Error \t: Please enter a valid Analyzer Profile Id.")
                    sys.exit(1)

        while self.bro_sample_path == "":
            self.bro_sample_path = raw_input('\033[92m' +
                "Enter Absolute sample directory path \t\t: " + '\033[0m')
            if self.bro_sample_path == "":
                print "Sample Directory Path can not be blank. Please provide valid directory path."

        if check_access(self.bro_sample_path, os.F_OK) and not os.path.exists(self.bro_sample_path):
            print "Path : [%s] doesn't exist. Creating directory path." % (self.bro_sample_path)
            os.makedirs(self.bro_sample_path)

        #self.bro_version = raw_input("Enter Bro Version : ") ''' Removing as path of code review, will use only unique marker for messageId '''

        global HOME_DIR

        self.env_path = raw_input('\033[92m' + "\nProvide path to store files. e.g. Log files, Counter files etc." + '\033[0m' + "[default:" + str(HOME_DIR) + "/atd-bro/] " + '\033[92m' + ": " + '\033[0m')

        self.file_remove = raw_input("\nDo you want to delete file on submission? " + '\033[93m' + "yes/no" + '\033[0m' ": ")
        global FILE_REMOVE_FLAG
        if self.env_path == "":
            SAMPLE_PARENT_DIR = HOME_DIR
        else:
            SAMPLE_PARENT_DIR = self.env_path
        if self.file_remove in yes:
            FILE_REMOVE_FLAG = "YES"
        elif self.file_remove in no:
            current_directory = os.getcwd()
            self.file_remove = raw_input('\033[92m' + "\nDirectory path to move the file's after submission" + '\033[0m' + " [default:" + str(SAMPLE_PARENT_DIR) + "/atd-bro/var/samples_backup/] " + '\033[92m' + ": " + '\033[0m')
            global file_move_path
            if self.file_remove == "":
                FILE_REMOVE_FLAG = "NO"
                file_move_path = str(SAMPLE_PARENT_DIR) + "/atd-bro/var/samples_backup/"

                '''
                if not current_directory.endswith('/'):
                    current_directory = current_directory + "/"
                if not self.bro_sample_path.endswith('/'):
                    self.bro_sample_path = self.bro_sample_path + "/"

                if current_directory == self.bro_sample_path :
                    print "Error : Can not move files to this path [" + str(current_directory) + "/atd-bro/var/samples_backup/] :"
                    print "Error : Path [" + self.bro_sample_path + "] can not be used to move the files."

                    self.file_remove = raw_input('\033[92m' + "\nPlease provide directory path to move the file's : " + '\033[0m')
                    if not self.file_remove.endswith('/'):
                        self.file_remove = self.file_remove + "/"

                    print "self.file_remove : [%s] self.bro_sample_path : [%s]" % (self.file_remove, self.bro_sample_path)

                    if self.file_remove == self.bro_sample_path :
                        print "Error : Failed to configure file move path. Try configuring again..."
                        sys.exit(0)
                    else:
                        file_move_path = self.file_remove + "/atd-bro/var/samples_backup/"
                else:    
                    file_move_path = SAMPLE_BACKUP_DIR
                '''

            else:
                file_move_path = self.file_remove + "/atd-bro/var/samples_backup/"
                
            if check_access(file_move_path, os.F_OK) and not os.path.exists(file_move_path):
                os.makedirs(file_move_path)

        config_file = BRO_CONF_FILE
	try:
            f = open(config_file, "w+")
	except:
	    print "User [%s] do not have permission to write in file [%s]" %(getpass.getuser(),config_file)
	    sys.exit(0)
        f.write(
            "[BRO CONFIG]\n\nSilent Mode\t\t\t: %s\n\nmatdip \t\t\t\t: %s\n\nusername \t\t\t: %s\n\nAnalyzer profile id \t\t: %s\n\nBro sample path \t\t: %s\n\nRemove file on submission\t: %s\n\nDirectory to move files\t\t: %s\n\nInstallation path\t\t: %s\n\n"
            % ("ON" if SILENT_MODE == 1 else "OFF", self.matdip, self.username, self.analyzer_profile_id, self.bro_sample_path, FILE_REMOVE_FLAG, file_move_path, SAMPLE_PARENT_DIR))
        f.close()
        print '\033[92m' + "\nNote :" + '\033[0m' + " Configuration is saved to file : %s " % (config_file)
        '''
        choice = raw_input( 
            "\nDo you want to start the REST submission? " + '\033[93m' + "yes/no : " + '\033[0m').lower()
        choice = "no"
        if choice in yes:
            mypath = sys.argv[0]
            print "mypath = %s %s" % (mypath, __file__)
            self.stop()
            print "Starting REST submission to ATD [%s]." % self.matdip
            self.show_configuration()
            self.start()
        elif choice in no:
            print "\nDone."
        else:
            sys.stdout.write("Please respond with 'yes' or 'no'")
        '''
        print '\033[92m' + "\nNote :" + '\033[0m' + " Please do \"START|RESTART\" the REST daemon to use latest configuration. "
        print "\nDone."

    def run_rest(self):
        logger.info("Starting REST submission daemon.")
        print "Starting REST submission daemon."
        w = Watcher()

        w.runner(self.matdip, self.username, self.password, self.analyzer_profile_id, self.bro_sample_path, self.silent_mode )

''' class Watcher(Daemon) '''
class Watcher(rest_Utils):
    DIRECTORY_TO_WATCH = ""
   
    def __init__(self):
        self.observer = Observer()

    def runner(self, matdip, username, password, analyzer_profile_id, bro_sample_path, silent_mode):
        SILENT_MODE = 0

        global LOCAL_SCAN_DIRECTORY_INTERVAL
        LOCAL_SCAN_DIRECTORY_INTERVAL = 0

        if silent_mode == "ON":
            SILENT_MODE = 1
            print "Note: Silent Mode Enabled!"
        else:
            SILENT_MODE = 0
            print "Note: Active Mode Enabled!"

        self.DIRECTORY_TO_WATCH = bro_sample_path
        event_handler = Handler(matdip, username, password, analyzer_profile_id, bro_sample_path, silent_mode)
        self.observer.schedule(
            event_handler, self.DIRECTORY_TO_WATCH, recursive=True)
        self.observer.start()
        try:
            global submission_time
            global last_file_counter_update_time
            global HIST_UPDATE_FLAG
            global COUNTER_FILE

            global HEARTBEAT_MISSED

            global DIR_SCAN_RUN_FLAG

            global COUNTER_HIST_FILE
            if not os.path.exists(COUNTER_HIST_FILE):
                tfp = open(COUNTER_HIST_FILE, 'w')
                tfp.close()

            while True:
                '''
                    Heartbeat message, if there is no sample submission is happening for 5 min to keep the session alive
                    REST script / daemon will send the heartbeat to the ATD device every 5 min's.
                    To avoid the session timeout heartbeat message is implemented.
                '''

                current_time = time.time()
                time_diff = current_time - submission_time

                '''
                    At every midnight file counter file entries will be moved i.e.appended to the file counter history file.
                    HIST_UPDATE_FLAG flag is used to track the update and to avoid multiple data append.
                '''
                if (dt.datetime.now().hour < 1) and (HIST_UPDATE_FLAG == 0):
                    logger.info("Midnight! 00hr! Time to append file counter file data to file counter history file! Appending.")
                    fp = open (COUNTER_HIST_FILE, 'a')
                    fp_read = open(COUNTER_FILE, 'r')
                    fp.write("_____________________ Appending File Counter Entries _____________________\n")
                    fp.write(fp_read.read())
                    fp.close()
                    fp_read.close()
                    open(COUNTER_FILE, 'w').close()
                    update_file_header()
                    HIST_UPDATE_FLAG = 1
                elif not (dt.datetime.now().hour == 00):
                    HIST_UPDATE_FLAG = 0

                '''
                    If timer (time difference) reaches 1 hr, do update the file count of submitted files to fileCounter.txt file.
                '''
                if (current_time - last_file_counter_update_time) > 3600:
                    global file_counter
                    updateCounterFile(file_counter)
                    logger.info("time difference : [%d] file_counter : [%d]" % ((current_time - last_file_counter_update_time),file_counter))
                    last_file_counter_update_time = time.time()

                '''                    
                    If timer exceeds 5 min of time interval without any new sample submission to ATD then to keep the login session
                    alive heartbeat will be sent to ATD.
                    Heartbeat will be sent every 5 min's if no sample is submitted else on sample submission timer will be resetted. 
                '''                    
                if (SILENT_MODE == 0):
                    if time_diff > 300:
                        DIR_SCAN_RUN_FLAG = False
                        sesuser_enc = loginInfo['sesuser_enc']
                        logger.info("Sending heartbeat to keep alive the login session.")
                        heartbeat(matdip, sesuser_enc)
                        if HEARTBEAT_MISSED >= 2:
                            logger.error("Host is unreachable. Login session is timed out by ATD. Please do restart the atdsubmitter daemon.")
                        current_time = time.time()
                        submission_time = time.time()
                        LOCAL_SCAN_DIRECTORY_INTERVAL = 0
                        time_diff = 0 
                    else:
                        current_time = time.time()

                '''
                    This is timer used to do check the samples present in configured sample directory.
                    At every 60Sec if there is no sample submission from last 60sec then directoy scan will happen.
                '''
                #logger.info("time_diff : [%d] LOCAL_SCAN_DIRECTORY_INTERVAL : [%d]" % (time_diff, LOCAL_SCAN_DIRECTORY_INTERVAL))

                if (time_diff - LOCAL_SCAN_DIRECTORY_INTERVAL) > 60:
                    LOCAL_SCAN_DIRECTORY_INTERVAL = time_diff
                    sesuser_enc = loginInfo['sesuser_enc']
                    #logger.info("Timer reached. ")
                    #logger.info("time_diff : [%d] LOCAL_SCAN_DIRECTORY_INTERVAL : [%d]" % (time_diff, LOCAL_SCAN_DIRECTORY_INTERVAL))
                    retCode = self.scan_dir_for_samples(matdip, sesuser_enc, analyzer_profile_id, ATDInfo['bro_version'], bro_sample_path, silent_mode)
                
                ''' check for disk space where scan directory path is mounted '''
                fs_free_size =  self.getFilesystemSize(bro_sample_path)
                if fs_free_size < 100:
                    logger.error("Disk Free space is critically low[%d]Mb for [%s] mounted filesystem. Please do cleanup to avoid failures." % (fs_free_size, bro_sample_path))
                    DISK_FREE_SPACE_CHECK_FLAG = True
                else:
                    DISK_FREE_SPACE_CHECK_FLAG = False

                time.sleep(5)

        except IOError as e:
            self.observer.stop()
            print "Error : [%s]" % (e)
            logger.error("Observer failed. Error:[%s]" % (e))

        self.observer.join()
  

class Handler(FileSystemEventHandler,rest_Utils):
    #@staticmethod

    matdip = ""
    username = ""
    password = ""
    analyzer_profile_id = ""
    bro_sample_path = ""
    silent_mode = ""

    MAX_FILE_SIZE = 120

    def __init__ (self, matdip, username, password, analyzer_profile_id, bro_sample_path, silent_mode):
        self.matdip = matdip
        self.username = username
        self.password = password
        self.analyzer_profile_id = analyzer_profile_id
        self.bro_sample_path = bro_sample_path
        self.silent_mode = silent_mode

        global ATDInfo
        sesuser_enc = loginInfo['sesuser_enc']

        logger.info("Sacanning dir \'%s\' for sample's present in directory." % (self.bro_sample_path))
        self.scan_dir_for_samples(self.matdip, sesuser_enc, self.analyzer_profile_id, ATDInfo['bro_version'], self.bro_sample_path, silent_mode)

    #Function    : check_file_size
    #Description : Check size of submitted file.
    #              If the file size is exceeded 120 Mb then reject the submission.
    #              If the file size is below max file size allowed then proceed for the file sbmission.

    def check_file_size(self, file_size):
        logger.info("check_file_size : file_size : [%d]" % (file_size))
        FILE_UPLOAD_FLAG = False
        size = file_size
        div = 1000
        total = (size / div)

        if total > div:
            get_kb = total
            #get_kb = (total / div)
            if get_kb > div:
                get_mb = (get_kb / div)
            else:
                get_mb = 1
            if get_mb > self.MAX_FILE_SIZE:
                FILE_UPLOAD_FLAG = False
                print "\nFile size is exceeded the maximum limit of [%d Mb] : current file size is [%d Mb]" % (self.MAX_FILE_SIZE, get_mb)
                logger.info("\nFile size is exceeded the maximum limit of [%d Mb] : current file size is [%d Mb]" % (self.MAX_FILE_SIZE, get_mb))
            else:
                FILE_UPLOAD_FLAG = True
                print "\nFile size is in limit. : [%d]" % (get_mb)
                logger.info("File size : %d Mb" % (get_mb))
        else:
            FILE_UPLOAD_FLAG = True
            print "\nupload the file."

        return(FILE_UPLOAD_FLAG)

    
    '''
        Function - on_any_event. This function will receive event when new file is created.
        On recived event file will be processed for further submission to ATD.
    '''
    def on_any_event(self, event):
        if event.is_directory:
            return None

        elif event.event_type == 'created':

            # Take any action here when a file is first created.
            print "Received created event - %s." % event.src_path
            logger.info("File received for submission : %s" % (event.src_path))

            if not os.path.exists(event.src_path):
                return

            statinfo = os.stat(event.src_path)
            FILE_UPLOAD_FLAG = self.check_file_size(statinfo.st_size)
    
            global ATDInfo
            print "FILE_UPLOAD_FLAG : [%s]" % FILE_UPLOAD_FLAG

            ''' 
                Check if file received for submission is complete
                else skip and take next file for submission. The 
                file skipped for now will be retried next time on next directory scan.
            '''
            SKIP_SUBMISSION = isFileExctractionCompleted(event.src_path)

            global loginInfo
            sesuser_enc = loginInfo['sesuser_enc']

            global submission_time
            global LOCAL_SCAN_DIRECTORY_INTERVAL
            submission_time = time.time()
            LOCAL_SCAN_DIRECTORY_INTERVAL = 0

            if (FILE_UPLOAD_FLAG == True) and (SKIP_SUBMISSION != 1):
        
                time.sleep(1)
    
                global SILENT_MODE

                silent_mode = "ON" if SILENT_MODE == 1 else "OFF"

                if SILENT_MODE == 1:
                    File_Upload(self.matdip, sesuser_enc, event.src_path, self.analyzer_profile_id, ATDInfo['bro_version'], silent_mode)
                elif SILENT_MODE == 0 and self.username and self.password and self.matdip and event.src_path:
                    ''' SILENT_MODE == 0 i.e. running in ACTIVE mode '''
                    try:
                        logger.info("About to submit sample for submission : %s" % (event.src_path))
                        logger.info("submission_time NOW : [%s]" % submission_time)
                        File_Upload(self.matdip, sesuser_enc, event.src_path,
                                    self.analyzer_profile_id, ATDInfo['bro_version'], silent_mode)

                    except:
                        logger.error('File_Upload : File submission failed')
                        print "file upload failed"

                else:
                    if SILENT_MODE == 0:
                        logger.error("File submission failed.")
                        help1()
               
            elif SKIP_SUBMISSION == 1:
                logger.error("Sample file[%s] is not completely extracted from network interface." % (event.src_path))
                logger.error("Skipping file[%s] submission for now." % (event.src_path))
            else:
                logger.error("File size limt is exceeded [< 120 Mb]. Failed to submit the file to ATD for analysis.")

            if not os.listdir(self.bro_sample_path) == []:
                ''' If extract sample file path is not empty. '''
                self.scan_dir_for_samples(self.matdip, sesuser_enc, self.analyzer_profile_id, ATDInfo['bro_version'], self.bro_sample_path, "ON" if SILENT_MODE == 1 else "OFF")


class MyDaemon(Daemon, Watcher, Handler):
    def run(self):
        while True:
            logger.info("Inside main run")
            logger.info("My Thread Id %d" % (threading.currentThread()))
            time.sleep(1)


'''
    main function.
'''
if __name__ == "__main__":
    daemon = MyDaemon(PID_FILE)

    ''' help string '''
    helpstring = set(['help','h','--help','hel', 'he','--h','--he','--hel'])

    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            ''' Starting daemon '''
            daemon.start()
        elif 'stop' == sys.argv[1]:
            ''' Stopping the daemon '''
            continue_flag = False
            time.sleep(1)
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            ''' Restarting the daemon '''
            continue_flag = False
            time.sleep(1)
            daemon.restart()
        elif 'configure' == sys.argv[1]:
            ''' Configuring the daemon '''
            daemon.configure()
        elif 'status' == sys.argv[1]:
            ''' Requesting Status of daemon '''
            daemon.status()
        elif 'stats' == sys.argv[1]:
            ''' Getting daemon REST submission statistics '''
            daemon.stats()
        elif sys.argv[1].lower() in helpstring:
            help()
        else:
            print "Unknown command.\n"
            help()
            sys.exit(2)
        sys.exit(0)
    else:
        help()

