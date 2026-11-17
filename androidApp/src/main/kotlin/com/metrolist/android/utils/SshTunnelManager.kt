package com.metrolist.android.utils

import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.metrolist.shared.network.GlobalProxySelector
import com.metrolist.shared.settings.Settings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import timber.log.Timber
import java.io.IOException
import java.net.Authenticator
import java.net.InetSocketAddress
import java.net.PasswordAuthentication
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI

object SshTunnelManager {
    sealed class TunnelState {
        data object Disconnected : TunnelState()
        data object Connecting : TunnelState()
        data class Connected(val host: String, val port: Int, val localPort: Int) : TunnelState()
        data class Error(val message: String) : TunnelState()
    }

    private val _state = MutableStateFlow<TunnelState>(TunnelState.Disconnected)
    val state = _state.asStateFlow()

    private var session: Session? = null
    private var tunnelJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO)

    fun initSystemProxySelector() {
        try {
            ProxySelector.setDefault(GlobalProxySelector)
        } catch (e: Exception) {
            Timber.e(e, "Failed to set default ProxySelector")
        }
    }

    @Synchronized
    fun startFromSettings() {
        val settings = Settings.shared
        if (!settings.sshTunnelEnabled) {
            stop()
            return
        }
        start(
            host = settings.sshTunnelHost,
            port = settings.sshTunnelPort,
            username = settings.sshTunnelUser,
            password = settings.sshTunnelPassword,
            remoteTargetPort = settings.sshTunnelRemotePort,
            proxyUser = settings.sshTunnelProxyUser,
            proxyPass = settings.sshTunnelProxyPassword,
        )
    }

    @Synchronized
    fun start(
        host: String,
        port: Int = 22,
        username: String,
        password: String? = null,
        remoteTargetPort: Int = 44501,
        proxyUser: String = "",
        proxyPass: String = "",
        privateKey: String? = null,
    ) {
        stop()

        if (host.isBlank() || username.isBlank()) {
            _state.value = TunnelState.Error("Host or username is empty")
            return
        }

        initSystemProxySelector()

        tunnelJob = scope.launch {
            _state.value = TunnelState.Connecting
            Timber.i("Starting SSH tunnel to $username@$host:$port")

            while (isActive) {
                var currentSession: Session? = null
                try {
                    val jsch = JSch()
                    if (!privateKey.isNullOrBlank()) {
                        jsch.addIdentity("customKey", privateKey.toByteArray(), null, null)
                    }

                    currentSession = jsch.getSession(username, host, port)
                    if (!password.isNullOrBlank()) {
                        currentSession.setPassword(password)
                    }

                    currentSession.setConfig("StrictHostKeyChecking", "no")
                    currentSession.setConfig("PreferredAuthentications", "publickey,password,keyboard-interactive")
                    currentSession.serverAliveInterval = 30
                    currentSession.serverAliveCountMax = 3
                    currentSession.connect(15000)

                    val localPort = currentSession.setPortForwardingL("127.0.0.1", 0, "127.0.0.1", remoteTargetPort)
                    session = currentSession

                    if (proxyUser.isNotBlank() && proxyPass.isNotBlank()) {
                        Authenticator.setDefault(
                            object : Authenticator() {
                                override fun getPasswordAuthentication(): PasswordAuthentication =
                                    PasswordAuthentication(proxyUser, proxyPass.toCharArray())
                            }
                        )
                    }

                    GlobalProxySelector.activeProxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", localPort))

                    _state.value = TunnelState.Connected(host, port, localPort)
                    Timber.i("SSH tunnel connected! 127.0.0.1:$localPort -> remote 127.0.0.1:$remoteTargetPort")

                    while (isActive && currentSession.isConnected) {
                        delay(5000)
                    }
                } catch (e: Exception) {
                    Timber.e(e, "SSH Tunnel error or disconnected")
                    _state.value = TunnelState.Error(e.message ?: "Connection failed")
                } finally {
                    try {
                        currentSession?.disconnect()
                    } catch (_: Exception) {}
                    if (session === currentSession) {
                        session = null
                        GlobalProxySelector.activeProxy = null
                    }
                }

                if (!isActive) break
                delay(10000)
            }
        }
    }

    @Synchronized
    fun stop() {
        tunnelJob?.cancel()
        tunnelJob = null
        try {
            session?.disconnect()
        } catch (_: Exception) {}
        session = null
        GlobalProxySelector.activeProxy = null
        _state.value = TunnelState.Disconnected
    }
}
