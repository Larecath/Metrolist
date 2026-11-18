package com.metrolist.shared.youtube.playback

import android.app.Service
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.Process
import android.webkit.WebView
import com.metrolist.shared.youtube.logging.YtLogger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class PoTokenService : Service() {
    private val sessions = mutableMapOf<String, Session>()

    override fun onCreate() {
        super.onCreate()
        liveInstances++
    }

    override fun onBind(intent: Intent): IBinder = Session().also { sessions[requireNotNull(intent.action)] = it }.messenger.binder

    override fun onUnbind(intent: Intent): Boolean {
        sessions.remove(intent.action)?.close()
        return false
    }

    override fun onDestroy() {
        sessions.values.forEach(Session::close)
        sessions.clear()
        super.onDestroy()
        liveInstances--
        // Chromium cannot unload; exit this bound-only process instead of retaining roughly 130 MB idle.
        Handler(Looper.getMainLooper()).post { if (liveInstances == 0) Process.killProcess(Process.myPid()) }
    }

    private companion object {
        var liveInstances = 0
    }

    private inner class Session {
        private val scope = MainScope()
        private var prewarmedWebView =
            try {
                WebView(applicationContext)
            } catch (error: Exception) {
                YtLogger.d("PoTokenService", "WebView prewarm failed type=${error::class.simpleName}")
                null
            }
        private var minter: BotGuardPoTokenMinter? = null
        private var visitorData: String? = null
        private var cookie: String? = null
        private var playerRequestToken: String? = null
        private var busy = false
        val messenger = Messenger(Handler(Looper.getMainLooper(), ::handleMessage))

        private fun handleMessage(message: Message): Boolean {
            if (message.what != PoTokenIpc.MINT) return false
            val replyTo = message.replyTo ?: return true
            val requestId = message.arg1
            val data = message.data
            val requestedVisitor = data.getString(PoTokenIpc.VISITOR_DATA) ?: return true
            val videoId = data.getString(PoTokenIpc.VIDEO_ID) ?: return true
            val proxyPort = data.getInt(PoTokenIpc.PROXY_PORT, 0)
            if (proxyPort > 0) {
                val pUser = data.getString(PoTokenIpc.PROXY_USER) ?: ""
                val pPass = data.getString(PoTokenIpc.PROXY_PASS) ?: ""
                if (pUser.isNotBlank()) {
                    System.setProperty("java.net.socks.username", pUser)
                    System.setProperty("java.net.socks.password", pPass)
                    java.net.Authenticator.setDefault(
                        object : java.net.Authenticator() {
                            override fun getPasswordAuthentication(): java.net.PasswordAuthentication {
                                return java.net.PasswordAuthentication(pUser, pPass.toCharArray())
                            }
                        }
                    )
                }
                com.metrolist.shared.network.GlobalProxySelector.activeProxy =
                    java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress("127.0.0.1", proxyPort))
                YtLogger.d("PoTokenService", "Proxy configured on port $proxyPort")
            }
            if (busy) return true
            busy = true
            scope.launch {
                val response = Bundle()
                try {
                    val requestedCookie = data.getString(PoTokenIpc.COOKIE)
                    if (
                        minter?.let { it.isDead || it.isExpired } != false ||
                        visitorData != requestedVisitor || cookie != requestedCookie
                    ) {
                        minter?.close()
                        minter = null
                        playerRequestToken = null
                        visitorData = requestedVisitor
                        cookie = requestedCookie
                        val webView = prewarmedWebView
                        prewarmedWebView = null
                        minter = BotGuardPoTokenMinter.create(this@PoTokenService, requestedVisitor, requestedCookie, videoId, webView)
                    }
                    val activeMinter = requireNotNull(minter)
                    val sessionToken = playerRequestToken ?: activeMinter.generate(requestedVisitor).also { playerRequestToken = it }
                    val videoToken = activeMinter.generate(videoId)
                    response.putString(PoTokenIpc.PLAYER_TOKEN, sessionToken)
                    response.putString(PoTokenIpc.VIDEO_TOKEN, videoToken)
                    response.putString(PoTokenIpc.VISITOR_DATA, requestedVisitor)
                    response.putLong(PoTokenIpc.EXPIRES_AT, activeMinter.expiresAtMs)
                } catch (error: CancellationException) {
                    if (!scope.isActive) throw error
                    resetMinter()
                } catch (_: Exception) {
                    resetMinter()
                } finally {
                    busy = false
                }
                runCatching {
                    replyTo.send(Message.obtain(null, PoTokenIpc.MINT, requestId, 0).apply { this.data = response })
                }
            }
            return true
        }

        private fun resetMinter() {
            minter?.close()
            minter = null
            playerRequestToken = null
            visitorData = null
            cookie = null
        }

        fun close() {
            prewarmedWebView?.destroy()
            prewarmedWebView = null
            scope.cancel()
            resetMinter()
        }
    }
}

internal object PoTokenIpc {
    const val MINT = 1
    const val VIDEO_ID = "videoId"
    const val VISITOR_DATA = "visitorData"
    const val COOKIE = "cookie"
    const val PLAYER_TOKEN = "playerRequestToken"
    const val VIDEO_TOKEN = "streamingDataToken"
    const val EXPIRES_AT = "expiresAtMs"
    const val PROXY_PORT = "proxyPort"
    const val PROXY_USER = "proxyUser"
    const val PROXY_PASS = "proxyPass"
}
