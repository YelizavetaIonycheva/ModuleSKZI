package org.pniei.moduleskzi.utils;

import android.app.Activity;
import android.content.Context;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.webkit.MimeTypeMap;

import androidx.appcompat.app.AlertDialog;
import androidx.documentfile.provider.DocumentFile;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import org.pniei.portal.R;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class Utils {
    public static int LENGTH_KEY = 32;

    /*public interface TypeDocument {
        int PASPORT = 0;
    }*/


    public static String TYPE_DOC_ARG = "type_document";

    public static void zipFile(File fileToZip, String fileName, ZipOutputStream zipOut) throws IOException {
        if (fileToZip.isHidden()) {
            return;
        }
        if (fileToZip.isDirectory()) {
            if (fileName.endsWith("/")) {
                zipOut.putNextEntry(new ZipEntry(fileName));
                zipOut.closeEntry();
            } else {
                zipOut.putNextEntry(new ZipEntry(fileName + "/"));
                zipOut.closeEntry();
            }
            File[] children = fileToZip.listFiles();
            for (File childFile : children) {
                zipFile(childFile, fileName + "/" + childFile.getName(), zipOut);
            }
            return;
        }
        FileInputStream fis = new FileInputStream(fileToZip);
        ZipEntry zipEntry = new ZipEntry(fileName);
        zipOut.putNextEntry(zipEntry);
        byte[] bytes = new byte[1024];
        int length;
        while ((length = fis.read(bytes)) >= 0) {
            zipOut.write(bytes, 0, length);
        }
        fis.close();
    }

    public static String getRandKey() {
        byte [] key = new byte[LENGTH_KEY];
        Random rand = new SecureRandom();
        rand.nextBytes(key);
        return byteArrayToHexString(key);
    }

    final protected static char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    public static String byteArrayToHexString(byte[] bytes) {
        char[] hexChars = new char[bytes.length*2];
        int v;

        for(int j=0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j*2] = hexArray[v>>>4];
            hexChars[j*2 + 1] = hexArray[v & 0x0F];
        }

        return new String(hexChars);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len/2];

        for(int i = 0; i < len; i+=2){
            data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }

        return data;
    }

    private static AlertDialog mWaitDialog = null;
    public static void showWaitDialog(Context context, String title) {
        closeWaitDialog();
        MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(context);
        if (title != null)
            builder.setTitle(title);
        mWaitDialog = builder.setView(R.layout.dialog_wait)
                .setCancelable(false)
                .show();
    }

    public static void closeWaitDialog() {
        if (mWaitDialog != null) {
            mWaitDialog.dismiss();
            mWaitDialog = null;
        }
    }

    public static String getMimeType(String nameFile) {
        String type = null;
        if(nameFile.lastIndexOf(".") != -1) {
            String ext = nameFile.substring(nameFile.lastIndexOf(".")+1);
            MimeTypeMap mime = MimeTypeMap.getSingleton();
            type = mime.getMimeTypeFromExtension(ext);
        }

        return type;
    }

    public static void hideKeyboardFrom(Context context, View view) {
        InputMethodManager imm = (InputMethodManager) context.getSystemService(Activity.INPUT_METHOD_SERVICE);
        imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
    }

    public static byte [] readFileFromZip(Context context, DocumentFile zipFile, String suffix) {
        byte[] buffer = new byte[1024];
        byte[] data;
        try {
            ZipInputStream zis = new ZipInputStream(context.getContentResolver().openInputStream(zipFile.getUri()));
            ZipEntry zipEntry = zis.getNextEntry();

            while(zipEntry != null) {
                if (!zipEntry.isDirectory()) {
                    if (zipEntry.getName().endsWith(suffix)) {
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            bos.write(buffer, 0, len);
                        }


                        data = bos.toByteArray();
                        bos.close();
                        zis.close();
                        return data;
                    }
                }
                zipEntry = zis.getNextEntry();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String intToHexString(int a) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%02x", a >> 24 & 0xFF));
        sb.append(String.format("%02x", a >> 16 & 0xFF));
        sb.append(String.format("%02x", a >> 8 & 0xFF));
        sb.append(String.format("%02x", a & 0xFF));
        return sb.toString().toUpperCase();
    }

    public static boolean checkIP(String ipAddress) {
        String[] fields = ipAddress.split("\\.");
        if((fields.length == 1) && (fields[0].compareTo("") == 0))
            return true;
        if(fields.length != 4)
            return false;
        try {
            for (int i = 0; i < 4; i++) {
                if(Integer.valueOf(fields[i]) < 0 || Integer.valueOf(fields[i]) > 255)
                    return false;
            }
        }
        catch (Exception e){
            return false;
        }
        return true;
    }

    public static int serArrayToInt(byte[] value) {
        if (value == null || value.length != 8)
            return 0;

        return (value[4] & 0x000000FF) |
                (value[5] << 8 & 0x0000FF00) |
                (value[6] << 16 & 0x00FF0000) |
                (value[7] << 24 & 0xFF000000);
    }

    public static String convertSerToStr(int ser) {
        final int LEN_STR = 8;
        final String STR_ZERO = "00000000";
        String serStr = ser + "";

        if (serStr.length() < LEN_STR) {
            serStr = STR_ZERO.substring(0, (LEN_STR - serStr.length())) + serStr;
        }
        return serStr;
    }

    public static String convertComplToStr(int compl) {
        final int LEN_STR = 3;
        final String STR_ZERO = "000";
        String complStr = compl + "";

        if (complStr.length() < LEN_STR) {
            complStr = STR_ZERO.substring(0, (LEN_STR - complStr.length())) + complStr;
        }
        return complStr;
    }

    public static String parsingDate(byte [] date) {
        if (date.length < 3)
            return "";

        if (date[1] == 0 || date[2] == 0)
            return "";

        StringBuilder sb = new StringBuilder();
        if (date[2] < 10)
            sb.append("0");
        sb.append(date[2]);
        sb.append(".");
        if (date[1] < 10)
            sb.append("0");
        sb.append(date[1]);
        sb.append(".");
        if (date[0] < 10)
            sb.append("0");
        sb.append(date[0]);
        return sb.toString();
    }

    public static void deleteRecursive(File fileOrDirectory) {
        if (fileOrDirectory.isDirectory())
            for (File child : fileOrDirectory.listFiles())
                deleteRecursive(child);

        fileOrDirectory.delete();
    }

    public static void deleteRecursive(String path) {
        File fileOrDirectory = new File(path);
        if (fileOrDirectory.isDirectory())
            for (File child : fileOrDirectory.listFiles())
                deleteRecursive(child);

        fileOrDirectory.delete();
    }

}
