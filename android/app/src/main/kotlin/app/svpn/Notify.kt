package app.svpn

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager

/** Message notifications: one per chat, tap opens the chat. Sound/vibration follow Android's channel settings. */
object Notify {
    /** The chat on screen (no notification for it), -1 = none. */
    @Volatile var visibleChat = -1

    private fun nm(ctx: Context) = ctx.getSystemService(NotificationManager::class.java)

    fun allowed(ctx: Context) = ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    fun post(ctx: Context, m: PushMsg, unread: Int) {
        if (m.chat == visibleChat || !allowed(ctx)) return
        // one channel per service, so Android's sound/vibration settings can differ
        val (channel, channelName) = if (m.service == T.SERVICE_SIGNAL) "signal" to "Signal messages" else "whatsapp" to "WhatsApp messages"
        nm(ctx).createNotificationChannel(NotificationChannel(channel, channelName, NotificationManager.IMPORTANCE_HIGH))
        val body = m.preview.ifEmpty { "[${T.KIND_NAMES.getOrElse(m.kind) { "media" }}]" }
        val open = Intent(ctx, ChatActivity::class.java).putExtra("chat", m.chat).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val n = Notification.Builder(ctx, channel)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle(m.chatName)
            .setContentText(if (m.sender.isEmpty()) body else "${m.sender}: $body")
            .setNumber(unread)
            .setWhen(System.currentTimeMillis())
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            .setContentIntent(PendingIntent.getActivity(ctx, m.chat, open, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
            .build()
        nm(ctx).notify(m.chat, n)
    }

    fun cancel(ctx: Context, chat: Int) = nm(ctx).cancel(chat)
}
