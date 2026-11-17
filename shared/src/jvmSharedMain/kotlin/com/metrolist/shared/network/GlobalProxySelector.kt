package com.metrolist.shared.network

import com.metrolist.shared.settings.Settings
import java.io.IOException
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI

object GlobalProxySelector : ProxySelector() {
    private val systemDefault: ProxySelector = getDefault() ?: object : ProxySelector() {
        override fun select(uri: URI?): List<Proxy> = listOf(Proxy.NO_PROXY)
        override fun connectFailed(uri: URI?, sa: SocketAddress?, ioe: IOException?) {}
    }

    @Volatile
    var activeProxy: Proxy? = null

    override fun select(uri: URI?): List<Proxy> {
        if (!shouldProxy(uri)) {
            return systemDefault.select(uri)
        }

        var proxy = activeProxy
        if (proxy == null && Settings.shared.sshTunnelEnabled) {
            // Wait up to 8 seconds for the tunnel to establish
            val start = System.currentTimeMillis()
            while (activeProxy == null && Settings.shared.sshTunnelEnabled && System.currentTimeMillis() - start < 8000) {
                try {
                    Thread.sleep(100)
                } catch (_: InterruptedException) {
                    break
                }
            }
            proxy = activeProxy
        }

        if (proxy != null) {
            return listOf(proxy)
        }
        return systemDefault.select(uri)
    }

    override fun connectFailed(uri: URI?, sa: SocketAddress?, ioe: IOException?) {
        systemDefault.connectFailed(uri, sa, ioe)
    }

    private fun shouldProxy(uri: URI?): Boolean {
        val host = uri?.host ?: return false
        if (host == "127.0.0.1" || host == "localhost") return false
        val tunnelHost = Settings.shared.sshTunnelHost
        if (tunnelHost.isNotBlank() && host.equals(tunnelHost, ignoreCase = true)) return false
        return true
    }
}
