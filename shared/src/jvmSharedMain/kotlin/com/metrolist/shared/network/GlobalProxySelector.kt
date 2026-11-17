package com.metrolist.shared.network

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
        val proxy = activeProxy
        if (proxy != null && shouldProxy(uri)) {
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
        return true
    }
}
