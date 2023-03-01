package org.pniei.moduleskzi.utils;

import android.content.Context;
import android.os.Environment;
import android.widget.Toast;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

public class Logger {
    private static final String FILE_NAME = "vpn_log.txt";
    private final int MAX_SIZE = 1048576;
    private File log_file = null;
    private DateFormat df = null;
    private Calendar mCalendar = null;
    private Context mContext;
    private static Logger logger;

    private Logger() {}

    public static Logger inc() {
        if(logger == null)
            logger = new Logger();
        return logger;
    }

    public void write(final String tag, final String message) {
        if(log_file != null && message != null) {
            new Thread(() -> {
                synchronized (log_file) {
                    try {
                        checkSize();
                        FileWriter fw = new FileWriter(log_file, true);
                        mCalendar = new GregorianCalendar();
                        mCalendar.setTimeZone(TimeZone.getTimeZone("GMT+03:00"));
                        fw.write(df.format(mCalendar.getTime()));
                        fw.write(tag);
                        fw.write(" : ");
                        fw.write(message);
                        fw.append('\n');
                        fw.flush();
                        fw.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }) .start();
        }
    }

    private void checkSize() {
        if(log_file != null) {
            try {
                if(log_file.exists() && log_file.length() > MAX_SIZE) {
                    File tempFile =  new File(mContext.getApplicationInfo().dataDir, "temp+"+FILE_NAME);
                    BufferedReader br = new BufferedReader(new FileReader(log_file));
                    BufferedWriter bw = new BufferedWriter(new FileWriter(tempFile));
                    String str = br.readLine();

                    while((str = br.readLine()) != null) {
                        bw.write(str);
                        bw.write('\n');
                    }
                    br.close();
                    bw.flush();
                    bw.close();

                    tempFile.renameTo(log_file);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

        }

    }

    public void init(Context context) {
        mContext = context;

        if(log_file == null) {
            log_file = new File(mContext.getApplicationInfo().dataDir, FILE_NAME);
            df = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss ");
        }

        if (!log_file.exists()) {
            try {
                log_file.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

	public String getLogString() {
        if(log_file != null) {
            byte [] buffer = new byte [1024];
            int len;
            try {
                FileInputStream fr = new FileInputStream(log_file);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                while((len = fr.read(buffer)) > 0) {
                    out.write(buffer, 0, len);
                }
                fr.close();
                out.close();
                return out.toString();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return "";
    }

    public void clear() {
        if(log_file != null) {
            log_file.delete();
        }
    }

    public void exportLogFile() {
        if(log_file != null) {
            char [] buffer = new char [1024];
            int len;
            File export_log_file = new File(Environment.getExternalStorageDirectory(), FILE_NAME);
            try {
                FileReader fr = new FileReader(log_file);
                FileWriter fw = new FileWriter(export_log_file);
                while((len = fr.read(buffer)) > 0) {
                    fw.write(buffer, 0, len);
                }
                fr.close();
                fw.flush();
                fw.close();
                Toast.makeText(mContext, "Скопировано в " + export_log_file.getCanonicalPath(), Toast.LENGTH_SHORT).show();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }

}
