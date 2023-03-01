package org.pniei.moduleskzi.utils;

import android.util.Base64;

public class CryptUtils {
    private static native void initcryptblock(byte [] key);
    private static native byte[] cryptblock(byte [] data, byte [] sp, int isFirst);
    private static native byte[] decryptblock(byte [] data, byte [] sp, int isFirst);
    private static native byte[] getizv();
    private static native int crc32(byte [] buf, int len);
    private static native byte[] gethash(byte [] buf);
    private static native byte[] cryptdata(byte [] data, byte[] key);
    private static native byte[] decryptdata(byte [] data, byte[] key);
    private static native byte[] cryptdataneyro(byte [] data, int lendata, byte[] key);
    private static native byte[] decryptdataneyro(byte [] data, int lendata, byte[] key);
    private static native byte[] gethmac(byte [] kbuf, byte [] tbuf);
    public static native void initcryptsound(byte[] keyOut, byte [] keyIn, int isCript);
    public static native void testmagma();

    private static final byte [] K = {(byte)0xD5, 0x76, (byte)0x90, 0x28, 0x04, 0x76, (byte)0xAC, 0x16, 0x71, 0x34, 0x6E, (byte)0xD5, (byte)0xFA, (byte)0x9A, (byte)0xE2, (byte)0xBC,
                                        0x49, (byte)0xDE, 0x1B, 0x5E, 0x1E, (byte)0xAB, (byte)0xB8, 0x53, 0x1E, 0x70, (byte)0x97, (byte)0xF0, (byte)0x9B, 0x55, (byte)0xCF, (byte)0xE3,
                                        0x14, 0x00, (byte)0xE8, 0x2E, (byte)0xBD, 0x73, 0x6B, (byte)0x8F, 0x14, (byte)0xF0, (byte)0xCC, 0x19, (byte)0x90, (byte)0xDE, (byte)0x85, 0x19,
                                        (byte)0xDE, (byte)0xEC, (byte)0xDA, (byte)0xD5, (byte)0xF8, 0x68, 0x48, 0x1D, 0x5A, (byte)0x96, (byte)0xE0, (byte)0xF2, 0x3A, (byte)0xFB, 0x17, 0x18};

    static {
        System.loadLibrary("cryptutils");
    }

//    public static void initCryptBlock(int idUser){
//        byte [] key = getHmac(K, Utils.idUserToByteArray(idUser));
//        initcryptblock(key);
//    }

    public static void testHMAC(){
        byte [] key = getHmac(K, Utils.hexStringToByteArray("0102030405060708090A"));
        initcryptblock(key);
    }

    public static byte[] cryptBlock(byte [] data, byte [] sp, int isFirst){
        return cryptblock(data, sp, isFirst);
    }

    public static byte[] decryptBlock(byte [] data, byte [] sp, int isFirst){
        return decryptblock(data, sp, isFirst);
    }

    public static byte[] getIZV(){
        return getizv();
    }

    public static int CRC32(byte [] buf, int len) {
        return crc32(buf, len);
    }

    public static byte[] getHmac(byte [] k, byte [] t) {
        return gethmac(k, t);
    }

//    public static byte[] getKeyForIdUser(int idUser) {
//        byte [] key64 = getHmac(K, Utils.idUserToByteArray(idUser));
//        byte [] key32 = new byte[32];
//        System.arraycopy(key64, 0, key32, 0, 32);
//        return key32;
//    }

    public static byte[] getHash(byte [] data) {
        return gethash(data);
    }

    public static byte[] cryptData(byte[] data, byte[] key) {
        if (data == null || data.length == 0 ||
                key == null || key.length != 32)
            return null;

        for(int i = 7; i < 32; i++)
            key[i] = 0;

        return cryptdata(data, key);
    }

    public static byte[] decryptData(byte[] data, byte[] key) {
        if (data == null || data.length == 0 ||
                key == null || key.length != 32)
            return null;

        for(int i = 7; i < 32; i++)
            key[i] = 0;

        return decryptdata(data, key);
    }

//    public static byte [] cryptDataNeyro(byte[] data, int lenData, byte[] key) {
//        if (data == null || data.length == 0 ||
//                lenData == 0 ||
//                key == null || key.length != 32 ||
//                data.length < lenData)
//            return null;
//        return cryptdataneyro(data, lenData, key);
//    }
//
//    public static byte [] decryptDataNeyro(byte[] data, int lenData, byte[] key) {
//        if (data == null || data.length == 0 ||
//                lenData == 0 ||
//                key == null || key.length != 32 ||
//                data.length < lenData)
//            return null;
//        return decryptdataneyro(data, lenData, key);
//    }
    
//    public static String cryptMessage(String message, int idUser) {
//        if (message == null || message.length() == 0)
//            return null;
//
//        String result = null;
//        byte [] key32 = getKeyForIdUser(idUser);
//        byte [] messageData = message.getBytes();
//        byte [] cryptBuf = cryptdataneyro(messageData, messageData.length, key32);
//        if (cryptBuf != null && cryptBuf.length > 0)
//            result = Base64.encodeToString(cryptBuf, Base64.NO_PADDING | Base64.NO_WRAP);
//        return result;
//    }
//
//    public static String decryptMessage(String message, int idUser) {
//        String result = null;
//
//        byte [] cryptBuf = Base64.decode(message, Base64.NO_PADDING | Base64.NO_WRAP);
//        if(cryptBuf != null) {
//            byte [] key32 = getKeyForIdUser(idUser);
//            byte [] decryptBuf = decryptdataneyro(cryptBuf, cryptBuf.length, key32);
//            if (decryptBuf != null && decryptBuf.length > 0)
//                result = new String(decryptBuf);
//        }
//        return result;
//    }
//
//    public static void initCryptSound(int idMy, int idUser, boolean isCrypt) {
//        if (isCrypt) {
//            //byte[] keyOut = getHmac(K, Utils.idUserToByteArray(idMy));
//            //byte[] keyIn = getHmac(K, Utils.idUserToByteArray(idUser));
//
//            byte[] keyOut = getKeyForIdUser(idMy);
//            byte[] keyIn = getKeyForIdUser(idUser);
//            initcryptsound(keyOut, keyIn, 1);
//        } else {
//            initcryptsound(null, null, 0);
//        }
//    }
}
