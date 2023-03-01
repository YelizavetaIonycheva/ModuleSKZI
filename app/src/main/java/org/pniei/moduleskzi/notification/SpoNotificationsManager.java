package org.pniei.moduleskzi.notification;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Build;
import android.util.Log;

import androidx.annotation.RequiresApi;

import org.pniei.moduleskzi.R;
import org.pniei.moduleskzi.activities.MainActivity;
import java.util.ArrayList;

public class SpoNotificationsManager {
    private static final String TAG = "SpoNotificationsManager";
    public static final String CHAT_NOTIFICATIONS_GROUP = "CHAT_NOTIF_GROUP";
    public static final String INTENT_REPLY_NOTIF_ACTION = "REPLY_ACTION";
    public static final String INTENT_MARK_AS_READ_ACTION = "MARK_AS_READ_ACTION";
    public static final String CHAT_ID = "CHAT_ID";
    private static SpoNotificationsManager instance;
    private final static int NOTIF_ID = 1;
    private final static int MESSAGE_NOTIF_ID = 3;
    private NotificationManager mNotificationManager;
    private Context mContext;
    private Notification mNotif;
    private ArrayList<Service> mServices;
    public static int notifcationsPriority = (Version.sdkAboveOrEqual(Version.API16_JELLY_BEAN_41) ? Notification.PRIORITY_MIN : 0);

    private SpoNotificationsManager(Context context) {
        mContext = context;
        mServices = new ArrayList<>();
        mNotificationManager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);

        String mNotificationTitle = context.getString(R.string.service_name);

        Intent notifIntent = new Intent(context, MainActivity.class);
        notifIntent.putExtra("Notification", true);
        notifIntent.addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        //notifIntent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);

        PendingIntent mNotifContentIntent;
        //mNotifContentIntent = PendingIntent.getBroadcast(context, 0, notifIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            mNotifContentIntent = PendingIntent.getActivity(context, 0, notifIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);
        } else {
            mNotifContentIntent = PendingIntent.getActivity(context, 0, notifIntent, PendingIntent.FLAG_UPDATE_CURRENT);
        }

        Bitmap bm = null;
        try {
            bm = BitmapFactory.decodeResource(context.getResources(), R.mipmap.ic_launcher);
        } catch (Exception ignored) { }

        mNotif = createNotification(context, mNotificationTitle, "", R.drawable.ic_notify, R.mipmap.ic_launcher, bm, mNotifContentIntent, notifcationsPriority, true);
    }

    public static synchronized SpoNotificationsManager ins(Context context) {
        if (instance == null) {
            Log.d(TAG, "SpoNotificationsManager Create");
            instance = new SpoNotificationsManager(context);
        }
        return instance;
    }

    public void startForeground(Service service) {
        Log.d(TAG, "startForeground " + service);
        service.startForeground(NOTIF_ID, mNotif);
        mServices.add(service);
    }

    public void stopForeground(Service service) {
        if (mServices.contains(service)) {
            Log.d(TAG, "stopForeground " + service);
            service.stopForeground(true);
            mServices.remove(service);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static void CreateChannel(Context context) {
        NotificationManager notificationManager =
                (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        // Create service notification channel
        String id = context.getString(R.string.notification_service_channel_id);
        CharSequence name = context.getString(R.string.content_title_notification_service);
        String description = context.getString(R.string.content_title_notification_service);
        int importance = NotificationManager.IMPORTANCE_LOW;
        NotificationChannel mChannel = new NotificationChannel(id, name, importance);
        mChannel.setDescription(description);
        mChannel.enableVibration(false);
        mChannel.setShowBadge(false);
        notificationManager.createNotificationChannel(mChannel);
    }

    public static Notification createNotification(Context context, String title, String message, int icon, int iconLevel, Bitmap largeIcon, PendingIntent intent, int priority, boolean isOngoingEvent) {
        //if (Version.sdkAboveOrEqual(Version.API26_O_80)) {
            return Api26Notification.createNotification(context, title, message, icon, iconLevel, largeIcon, intent, isOngoingEvent,priority);
       // }
    }

}
