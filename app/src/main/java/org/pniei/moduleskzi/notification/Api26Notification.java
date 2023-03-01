package org.pniei.moduleskzi.notification;

import android.annotation.TargetApi;
import android.app.Notification;
import android.app.PendingIntent;
import android.content.Context;
import android.graphics.Bitmap;

import org.pniei.moduleskzi.R;

@TargetApi(26)
public class Api26Notification {
    public static Notification createNotification(Context context, String title, String message, int icon, int level, Bitmap largeIcon, PendingIntent intent, boolean isOngoingEvent,int priority) {
        Notification notif;

        if (largeIcon != null) {
            notif = new Notification.Builder(context, context.getString(R.string.notification_service_channel_id))
                    .setContentTitle(title)
                    .setContentText(message)
                    .setSmallIcon(icon, level)
                    .setLargeIcon(largeIcon)
                    .setContentIntent(intent)
                    .setCategory(Notification.CATEGORY_SERVICE)
                    .setVisibility(Notification.VISIBILITY_SECRET)
                    .setPriority(priority)
                    .build();
        } else {
            notif = new Notification.Builder(context, context.getString(R.string.notification_service_channel_id))
                    .setContentTitle(title)
                    .setContentText(message)
                    .setSmallIcon(icon, level)
                    .setContentIntent(intent)
                    .setCategory(Notification.CATEGORY_SERVICE)
                    .setVisibility(Notification.VISIBILITY_SECRET)
                    .setPriority(priority)
                    .build();
        }

        return notif;
    }


}
