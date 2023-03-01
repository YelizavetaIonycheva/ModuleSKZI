package org.pniei.moduleskzi.notification;

import android.content.Context;
import android.content.res.Configuration;
import android.os.Build;

public class Version {

    public static final int API03_CUPCAKE_15 = 3;
    public static final int API04_DONUT_16 = 4;
    public static final int API05_ECLAIR_20 = 5;
    public static final int API06_ECLAIR_201 = 6;
    public static final int API07_ECLAIR_21 = 7;
    public static final int API08_FROYO_22 = 8;
    public static final int API09_GINGERBREAD_23 = 9;
    public static final int API10_GINGERBREAD_MR1_233 = 10;
    public static final int API11_HONEYCOMB_30 = 11;
    public static final int API12_HONEYCOMB_MR1_31X = 12;
    public static final int API13_HONEYCOMB_MR2_32  = 13;
    public static final int API14_ICE_CREAM_SANDWICH_40 = 14;
    public static final int API15_ICE_CREAM_SANDWICH_403 = 15;
    public static final int API16_JELLY_BEAN_41 = 16;
    public static final int API17_JELLY_BEAN_42 = 17;
    public static final int API18_JELLY_BEAN_43 = 18;
    public static final int API19_KITKAT_44 = 19;
    public static final int API21_LOLLIPOP_50 = 21;
    public static final int API22_LOLLIPOP_51 = 22;
    public static final int API23_MARSHMALLOW_60 = 23;
    public static final int API24_NOUGAT_70 = 24;
    public static final int API25_NOUGAT_71 = 25;
    public static final int API26_O_80 = 26;
    public static final int API28_PIE_90 = 28;
    public static final int API29_ANDROID_10 = 29;

    private static final int buildVersion = Build.VERSION.SDK_INT;
//		API03_CUPCAKE_15;
//		8; // 2.2
//		7; // 2.1

    public static boolean isXLargeScreen(Context context)
    {
        return (context.getResources().getConfiguration().screenLayout & Configuration.SCREENLAYOUT_SIZE_MASK) >= Configuration.SCREENLAYOUT_SIZE_XLARGE;
    }

    public static final boolean sdkAboveOrEqual(int value) {
        return buildVersion >= value;
    }

}