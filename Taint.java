/*
 *
 * Author: Zhe Jin & Yupeng Hu (yphu@hnu.edu.cn)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dalvik.system;

import java.nio.ByteBuffer;

/**
 * Provides a Taint interface for the Dalvik VM. This class is used for
 * implementing Taint Source and Sink functionality.
 * 
 */
public final class Taint {

    public static final int TAINT_CLEAR         = 0x00000000;
    public static final int TAINT_LOCATION      = 0x00000001;
    public static final int TAINT_CONTACTS      = 0x00000002;
    public static final int TAINT_MIC           = 0x00000004;
    public static final int TAINT_PHONE_NUMBER  = 0x00000008;
    public static final int TAINT_LOCATION_GPS  = 0x00000010;
    public static final int TAINT_LOCATION_NET  = 0x00000020;
    public static final int TAINT_LOCATION_LAST = 0x00000040;
    public static final int TAINT_CAMERA        = 0x00000080;
    public static final int TAINT_ACCELEROMETER = 0x00000100;
    public static final int TAINT_SMS           = 0x00000200;
    public static final int TAINT_IMEI          = 0x00000400;
    public static final int TAINT_IMSI          = 0x00000800;
    public static final int TAINT_ICCID         = 0x00001000;
    public static final int TAINT_DEVICEID      = 0x00002000;
    public static final int TAINT_ACCOUNT       = 0x00004000;
    public static final int TAINT_HISTORY       = 0x00008000;
    public static final int TAINT_SIMSERIANUMBER  = 0x00010000;
    public static final int TAINT_SUBSCRIBERID  = 0x00010001;
    public static final int TAINT_inputText = 0x00010002;
    public static final int TAINT_LOCATION_Latitude = 0x00010004;
    public static final int TAINT_LOCATION_Longitude = 0x00010008;
    public static final int TAINT_provider_query = 0x00010010;
    public static final int TAINT_network_type = 0x00010011;
    public static final int TAINT_network_state = 0x00010012;
    public static final int TAINT_network_subtype = 0x00010014;
    public static final int TAINT_sharepreference = 0x00010018;

    public static final int INTENT_LOCATION      = 0x00100001;
    public static final int INTENT_CONTACTS      = 0x00100002;
    public static final int INTENT_MIC           = 0x00100004;
    public static final int INTENT_PHONE_NUMBER  = 0x00100008;
    public static final int INTENT_LOCATION_GPS  = 0x00100010;
    public static final int INTENT_LOCATION_NET  = 0x00100020;
    public static final int INTENT_LOCATION_LAST = 0x00100040;
    public static final int INTENT_CAMERA        = 0x00100080;
    public static final int INTENT_ACCELEROMETER = 0x00100100;
    public static final int INTENT_SMS           = 0x00100200;
    public static final int INTENT_IMEI          = 0x00100400;
    public static final int INTENT_IMSI          = 0x00100800;
    public static final int INTENT_ICCID         = 0x00101000;
    public static final int INTENT_DEVICEID      = 0x00102000;
    public static final int INTENT_ACCOUNT       = 0x00104000;
    public static final int INTENT_HISTORY       = 0x00108000;
    public static final int INTENT_SIMSERIANUMBER  = 0x00110000;
    public static final int INTENT_SUBSCRIBERID  = 0x00110001;
    public static final int INTENT_inputText = 0x00110002;
    public static final int INTENT_LOCATION_Latitude = 0x00110004;
    public static final int INTENT_LOCATION_Longitude = 0x00110008;
    public static final int INTENT_provider_query = 0x00110010;
    public static final int INTENT_network_type = 0x00110011;
    public static final int INTENT_network_state = 0x00110012;
    public static final int INTENT_network_subtype = 0x00110014;
    public static final int INTENT_sharepreference = 0x00110018;

    public static final int intent_action=0x00000101;
    public static final int intent_data=0x00000102;
    public static final int intent_categories=0x00000104;
    public static final int intent_bundle=0x00000108;
    public static final int intent_extra=0x00000110;
    public static final int intent_byteExtra=0x00000111;
    public static final int intent_byteArrayExtra = 0x00000112;
    public static final int intent_charArrayExtra = 0x00000114;
    public static final int intent_charExtra = 0x00000118;
    public static final int intent_bundleExtra = 0x00000120;
    public static final int intent_booleanExtra = 0x00000121;
    public static final int intent_booleanArrayExtra = 0x00000122;
    public static final int intent_dataString = 0x00000124;
    public static final int intent_floatArrayExtra = 0x00000128;
    public static final int intent_flags = 0x00000140;
    public static final int intent_floatExtra = 0x00000141;
    public static final int intent_intArrayExtra = 0x00000142;
    public static final int intent_intExtra = 0x00000144;
    public static final int intent_integerArrayListExtra = 0x00000148;
    public static final int intent_stringExtra = 0x00000180;
    public static final int intent_type = 0x00000181;
    public static final int intent_parseUri = 0x00000182;
    public static final int intent_parseIntent = 0x00000184;
    public static final int intent_scheme = 0x00000188;
    public static final int intent_shortExtra = 0x00000201;
    public static final int intent_longExtra = 0x00000202;
    public static final int intent_douleExtra = 0x00000204;
    public static final int intent_stringArrayListExtra = 0x00000208;
    public static final int intent_charSequenceArrayList = 0x00000210;
    public static final int intent_shortArrayExtra = 0x00000211;
    public static final int intent_longArrayExtra = 0x00000212;
    public static final int intent_doubleArrayExtra = 0x00000214;


    // how many bytes of tainted network output data to print to log?
    public static final int dataBytesToLog = 100;

    public static String intentTaintLeak(String taintData){
        String res=null;
        if(taintData==null) return null;
        int tag = getTaintString(taintData);
        switch (tag){
            case 0x00100001:
                res = "location";
                break;
            case 0x00100002:
                res = "contacts";
                break;
            case 0x00100004:
                res = "mic";
                break;
            case 0x00100008:
                res = "phone number";
                break;
            case 0x00100010:
                res = "location_gps";
                break;
            case 0x00100020:
                res = "location_net";
                break;
            case 0x00100040:
                res = "location_last";
                break;
            case 0x00100080:
                res = "camera";
                break;
            case 0x00100100:
                res = "accelerometer";
                break;
            case 0x00100200:
                res = "sms";
                break;
            case 0x00100400:
                res = "IMEI";
                break;
            case 0x00100800:
                res = "IMSI";
                break;
            case 0x00101000:
                res ="ICCID";
                break;
            case 0x00102000:
                res = "deviceId";
                break;
            case 0x00104000:
                res = "account";
                break;
            case 0x00108000:
                res = "browse-mark";
                break;
            case 0x00110000:
                res = "simserianumber";
                break;
            case 0x00110001:
                res = "subscriberId";
                break;
            case 0x00110002:
                res = "user_inputText";
                break;
            case 0x00000101:
                res="intent_action";
                break;
            case 0x00000102:
                res="intent_data";
                break;
            case 0x00000104:
                res="intent_categories";
                break;
            case 0x00000108:
                res="intent_bundle";
                break;
            case 0x00000110:
                res="intent_extra";
                break;
            case 0x00000111:
                res="intent_byteExtra";
                break;
            case 0x00000112:
                res="intent_byteArrayExtra";
                break;
            case 0x00000114:
                res="intent_charArrayExtra";
                break;
            case 0x00000118:
                res="intent_charExtra";
                break;
            case 0x00000120:
                res="intent_bundleExtra";
                break;
            case 0x00000121:
                res="intent_booleanExtra";
                break;
            case 0x00000122:
                res="intent_booleanArrayExtra";
                break;
            case 0x00000124:
                res="intent_dataString";
                break;
            case 0x00000128:
                res="intent_floatArrayExtra";
                break;
            case 0x00000140:
                res="intent_flags";
                break;
            case 0x00000141:
                res="intent_floatExtra";
                break;
            case 0x00000142:
                res="intent_intArrayExtra";
                break;
            case 0x00000148:
                res="intent_integerArrayListExtra";
                break;
            case 0x00000180:
                res="intent_stringExtra";
                break;
            case 0x00000181:
                res="intent_type";
                break;
            case 0x00000182:
                res="intent_parseUri";
                break;
            case 0x00000184:
                res="intent_parseIntent";
                break;
            case 0x00000188:
                res="intent_scheme";
                break;
            case 0x00000201:
                res="intent_shortExtra";
                break;
            case 0x00000202:
                res="intent_longExtra";
                break;
            case 0x00000204:
                res="intent_douleExtra";
                break;
            case 0x00000208:
                res="intent_stringArrayListExtra";
                break;
            case 0x00000210:
                res="intent_charSequenceArrayList";
                break;
            case 0x00000211:
                res="intent_shortArrayExtra";
                break;
            case 0x00000212:
                res="intent_longArrayExtra";
                break;
            case 0x00000214:
                res="intent_doubleArrayExtra";
                break;
            case INTENT_LOCATION_Latitude:
                res = "location_Latitude";
                break;
            case INTENT_LOCATION_Longitude:
                res = "location_Longitude";
                break;
            case INTENT_provider_query:
                res = "provider query";
                break;
            case INTENT_network_state:
                res = "network state";
                break;
            case INTENT_network_subtype:
                res = "network subtype";
                break;
            case INTENT_network_type:
                res = "network type";
                break;
            case INTENT_sharepreference:
                res = "sharepreference";
                break;

                default:
                    break;
        }
        return  res;
    }

    public static int taintDataOutIntent(String taintData){
        int tag = getTaintString(taintData);
        int newTag = TAINT_CLEAR;

        switch(tag){
            case TAINT_LOCATION:
                newTag = INTENT_LOCATION;
                break;
            case TAINT_CONTACTS:
                newTag = INTENT_CONTACTS;
                break;
            case TAINT_PHONE_NUMBER:
                newTag = INTENT_PHONE_NUMBER;
                break;
            case TAINT_IMEI:
                newTag = INTENT_IMEI;
                break;
            case TAINT_DEVICEID :
                newTag = INTENT_DEVICEID;
                break;
            case TAINT_SIMSERIANUMBER :
                newTag = INTENT_SIMSERIANUMBER;
                break;
            case TAINT_SMS:
                newTag = INTENT_SMS;
                break;
            case TAINT_HISTORY:
                newTag = INTENT_HISTORY;
                break;
            case TAINT_SUBSCRIBERID:
                newTag = INTENT_SUBSCRIBERID;
                break;
            case TAINT_inputText:
                newTag = INTENT_inputText;
                break;
            case TAINT_provider_query:
                newTag = INTENT_provider_query;
                break;
            case TAINT_network_state:
                newTag = INTENT_network_state;
                break;
            case TAINT_network_type:
                newTag = INTENT_network_type;
                break;
            case TAINT_network_subtype:
                newTag = INTENT_network_subtype;
                break;
            case TAINT_sharepreference:
                newTag = INTENT_sharepreference;
                break;
            case TAINT_LOCATION_NET:
                newTag = INTENT_LOCATION_NET;
                break;
            case TAINT_LOCATION_GPS:
                newTag = INTENT_LOCATION_GPS;
                break;
            default:
                break;
        }
        log("receiverLeak: tag-"+tag+"-newTag-"+newTag);
        if(newTag == TAINT_CLEAR){
            addTaintString(taintData,intent_stringExtra);
        }else {
            addTaintString(taintData,newTag);
        }
        log("receiverLeak: tag-"+tag+"-newTag-"+newTag);
        return newTag;
    }

    public static String whatTaintInSetIntent(int tag){
        String taint=null;
        switch(tag){
            case 0x00000001:
                taint = "Location";
                break;
            case 0x00000002:
                taint = "Contacts";
                break;
            case 0x00000008:
                taint = "PhoneNumber";
                break;
            case 0x00000400:
                taint = "IMEI";
                break;
            case 0x00002000:
                taint = "DeviceId";
                break;
            case 0x00010000:
                taint = "SimSerialNumber";
                break;
            case 0x00000200:
                taint = "SMS";
                break;
            case 0x00008000:
                taint = "bookmarks";
                break;
            case 0x00010001:
                taint = "subscriberid";
                break;
            case 0x00010002:
                taint = "inputText";
                break;
            case TAINT_LOCATION_Latitude:
                taint = "location_Latitude";
                break;
            case TAINT_LOCATION_Longitude:
                taint = "location_Longitude";
            case TAINT_network_state:
                taint = "network state";
                break;
            case TAINT_network_subtype:
                taint = "network subtype";
                break;
            case TAINT_network_type:
                taint = "network type";
                break;
            case TAINT_sharepreference:
                taint = "sharepreference";
                break;
            case TAINT_LOCATION_GPS:
                taint = "location_gps";
                break;
            case TAINT_LOCATION_NET:
                taint = "location_net";
                break;
            case TAINT_provider_query:
                taint = "provider query";
                break;
                default:
                    break;
        }
        return taint;
    }

    /**
     * Updates the target String's taint tag.
     *
     * @param str
     *	    the target string
     * @param tag
     *	    tag to update (bitwise or) onto the object
     */
    native public static void addTaintString(String str, int tag);
    
    /**
     * Updates the target Object array's taint tag.
     *
     * @param array
     *	    the target object array
     * @param tag
     *	    tag to update (bitwise or) onto the object array
     */
    native public static void addTaintObjectArray(Object[] array, int tag);

    /**
     * Updates the target boolean array's taint tag.
     *
     * @param array
     *	    the target boolean array
     * @param tag
     *	    tag to update (bitwise or) onto the boolean array
     */
    native public static void addTaintBooleanArray(boolean[] array, int tag);

    /**
     * Updates the target char array's taint tag.
     *
     * @param array
     *	    the target char array
     * @param tag
     *	    tag to update (bitwise or) onto the char array
     */
    native public static void addTaintCharArray(char[] array, int tag);

    /**
     * Updates the target byte array's taint tag.
     *
     * @param array
     *	    the target byte array
     * @param tag
     *	    tag to update (bitwise or) onto the byte array
     */
    native public static void addTaintByteArray(byte[] array, int tag);
    
    /**
     * Updates the target direct ByteBuffer's taint tag.
     *
     * @param dByteBuffer 
     *	    the target direct ByteBuffer
     * @param tag
     *      tag to update (bitwise or) onto the direct ByteBuffer
     */
    public static void addTaintDirectByteBuffer(ByteBuffer dByteBuffer, int tag) {
        if (dByteBuffer.isDirect()) {
            dByteBuffer.addDirectByteBufferTaint(tag);
        }
    }

    /**
     * Updates the target int array's taint tag.
     *
     * @param array
     *	    the target int array
     * @param tag
     *	    tag to update (bitwise or) onto the int array
     */
    native public static void addTaintIntArray(int[] array, int tag);
    
    /**
     * Updates the target short array's taint tag.
     *
     * @param array
     *	    the target short array
     * @param tag
     *	    tag to update (bitwise or) onto the int array
     */
    native public static void addTaintShortArray(short[] array, int tag);

    /**
     * Updates the target long array's taint tag.
     *
     * @param array
     *	    the target long array
     * @param tag
     *	    tag to update (bitwise or) onto the long array
     */
    native public static void addTaintLongArray(long[] array, int tag);

    /**
     * Updates the target float array's taint tag.
     *
     * @param array
     *	    the target float array
     * @param tag
     *	    tag to update (bitwise or) onto the float array
     */
    native public static void addTaintFloatArray(float[] array, int tag);

    /**
     * Updates the target double array's taint tag.
     *
     * @param array
     *	    the target double array
     * @param tag
     *	    tag to update (bitwise or) onto the double array
     */
    native public static void addTaintDoubleArray(double[] array, int tag);
    
    /**
     * Add taint to a primitive boolean value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static boolean addTaintBoolean(boolean val, int tag);
    
    /**
     * Add taint to a primitive char value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static char addTaintChar(char val, int tag);
    
    /**
     * Add taint to a primitive byte value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static byte addTaintByte(byte val, int tag);

    /**
     * Add taint to a primitive int value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static int addTaintInt(int val, int tag);
    
    /**
     * Add taint to a primitive short value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static short addTaintShort(short val, int tag);

    /**
     * Add taint to a primitive long value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static long addTaintLong(long val, int tag);

    /**
     * Add taint to a primitive float value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static float addTaintFloat(float val, int tag);

    /**
     * Add taint to a primitive double value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static double addTaintDouble(double val, int tag);

    /**
     * Get the current taint tag from a String.
     *
     * @param str
     *	    the target String
     * @return the taint tag
     */
    native public static int getTaintString(String str);

    /**
     * Get the current taint tag from an Object array.
     *
     * @param array 
     *	    the target Object array
     * @return the taint tag
     */
    native public static int getTaintObjectArray(Object[] array);

    /**
     * Get the current taint tag from a boolean array.
     *
     * @param array 
     *	    the target boolean array
     * @return the taint tag
     */
    native public static int getTaintBooleanArray(boolean[] array);

    /**
     * Get the current taint tag from a char array.
     *
     * @param array 
     *	    the target char array
     * @return the taint tag
     */
    native public static int getTaintCharArray(char[] array);

    /**
     * Get the current taint tag from a byte array.
     *
     * @param array 
     *	    the target byte array
     * @return the taint tag
     */
    native public static int getTaintByteArray(byte[] array);

    /**
     * Get the current taint tag from a direct ByteBuffer.
     *
     * @param dByteBuffer 
     *	    the target direct ByteBuffer
     * @return the taint tag
     */
    public static int getTaintDirectByteBuffer(ByteBuffer dByteBuffer) {
        if (dByteBuffer.isDirect()) {
            return dByteBuffer.getDirectByteBufferTaint();
        } else {
            return -1;
        }
    }

    /**
     * Get the current taint tag from an int array.
     *
     * @param array 
     *	    the target int array
     * @return the taint tag
     */
    native public static int getTaintIntArray(int[] array);

    /**
     * Get the current taint tag from a short array.
     *
     * @param array 
     *	    the target short array
     * @return the taint tag
     */
    native public static int getTaintShortArray(short[] array);

    /**
     * Get the current taint tag from a long array.
     *
     * @param array 
     *	    the target long array
     * @return the taint tag
     */
    native public static int getTaintLongArray(long[] array);

    /**
     * Get the current taint tag from a float array.
     *
     * @param array 
     *	    the target float array
     * @return the taint tag
     */
    native public static int getTaintFloatArray(float[] array);

    /**
     * Get the current taint tag from a double array.
     *
     * @param array 
     *	    the target double array
     * @return the taint tag
     */
    native public static int getTaintDoubleArray(double[] array);

    /**
     * Get the current taint tag from a primitive boolean.
     *
     * @param val
     *	    the target boolean
     * @return the taint tag
     */
    native public static int getTaintBoolean(boolean val);

    /**
     * Get the current taint tag from a primitive char.
     *
     * @param val
     *	    the target char 
     * @return the taint tag
     */
    native public static int getTaintChar(char val);

    /**
     * Get the current taint tag from a primitive byte.
     *
     * @param val
     *	    the target byte 
     * @return the taint tag
     */
    native public static int getTaintByte(byte val);

    /**
     * Get the current taint tag from a primitive int.
     *
     * @param val
     *	    the target int 
     * @return the taint tag
     */
    native public static int getTaintInt(int val);
    
    /**
     * Get the current taint tag from a primitive short.
     *
     * @param val
     *	    the target short 
     * @return the taint tag
     */
    native public static int getTaintShort(short val);

    /**
     * Get the current taint tag from a primitive long.
     *
     * @param val
     *	    the target long 
     * @return the taint tag
     */
    native public static int getTaintLong(long val);

    /**
     * Get the current taint tag from a primitive float.
     *
     * @param val
     *	    the target float 
     * @return the taint tag
     */
    native public static int getTaintFloat(float val);

    /**
     * Get the current taint tag from a primitive double.
     *
     * @param val
     *	    the target double 
     * @return the taint tag
     */
    native public static int getTaintDouble(double val);

    /**
     * Get the current taint tag from an Object reference.
     *
     * @param obj
     *	    the target Object reference
     * @return the taint tag
     */
    native public static int getTaintRef(Object obj);
    
    /**
     * Get the taint tag from a file identified by a descriptor.
     *
     * @param fd
     *	    the target file descriptor
     * @return the taint tag
     */
    native public static int getTaintFile(int fd);
    
    /**
     * add a taint tag to a file identified by a descriptor
     *
     * @param fd
     *	    the target file descriptor
     * @param tag
     *	    the tag to add (bitwise or) to the file
     */
    native public static void addTaintFile(int fd, int tag);

    /**
     * Logging utility accessible from places android.util.Log
     * is not.
     *
     * @param msg
     *	    the message to log
     */
    native public static void log(String msg);


    /**
     * Logging utility to obtain the file path for a file descriptor
     *
     * @param fd
     *	    the file descriptor
     */
    native public static void logPathFromFd(int fd);

    /**
     * Logging utility to obtain the peer IP addr for a file descriptor
     *
     * @param fd
     *	    the file descriptor
     */
    native public static void logPeerFromFd(int fd);
}
