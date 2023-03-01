package org.pniei.moduleskzi.utils;

public class Signature {
    static {
        System.loadLibrary("signature");
    }

    public static native byte[] ecpform(byte [] key, byte [] data);
    public static native int ecpcontrol(byte [] key, byte [] data, byte [] ecp);
    public static native byte[] getkeyform(int numKey);
    public static native byte[] getkeycontrol(int numKey);
}
