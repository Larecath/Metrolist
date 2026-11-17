package com.metrolist.android.utils

import android.util.Log
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.UserInfo
import com.metrolist.shared.network.GlobalProxySelector
import com.metrolist.shared.settings.Settings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.Authenticator
import java.net.InetSocketAddress
import java.net.PasswordAuthentication
import java.net.Proxy
import java.net.ProxySelector

object SshTunnelManager {
    private const val TAG = "SshTunnelManager"

    sealed class TunnelState {
        data object Disconnected : TunnelState()
        data object Connecting : TunnelState()
        data class Connected(val host: String, val port: Int, val localPort: Int) : TunnelState()
        data class Error(val message: String) : TunnelState()
    }

    private val _state = MutableStateFlow<TunnelState>(TunnelState.Disconnected)
    val state = _state.asStateFlow()

    @Volatile
    private var session: Session? = null
    private var tunnelJob: Job? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var currentConfigKey: String? = null

    init {
        try {
            JSch.setLogger(object : com.jcraft.jsch.Logger {
                override fun isEnabled(level: Int): Boolean = true
                override fun log(level: Int, message: String) {
                    Log.d(TAG, "[JSCH $level] $message")
                }
            })
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to set JSch logger", e)
        }
    }

    fun initSystemProxySelector() {
        try {
            ProxySelector.setDefault(GlobalProxySelector)
            Log.i(TAG, "GlobalProxySelector installed as system default")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set default ProxySelector", e)
        }
    }

    @Synchronized
    fun startFromSettings() {
        val settings = Settings.shared
        if (!settings.sshTunnelEnabled) {
            Log.i(TAG, "SSH Tunnel disabled in settings")
            stop()
            return
        }
        val configKey = "${settings.sshTunnelHost}:${settings.sshTunnelPort}:${settings.sshTunnelUser}:${settings.sshTunnelPassword}:${settings.sshTunnelRemotePort}:${settings.sshTunnelProxyUser}:${settings.sshTunnelProxyPassword}"
        if (session?.isConnected == true && currentConfigKey == configKey) {
            Log.i(TAG, "SSH tunnel already connected with current config")
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
        val configKey = "$host:$port:$username:$password:$remoteTargetPort:$proxyUser:$proxyPass"
        if (session?.isConnected == true && currentConfigKey == configKey) {
            Log.i(TAG, "Tunnel already active for $username@$host:$port")
            return
        }

        stop()

        if (host.isBlank() || username.isBlank()) {
            _state.value = TunnelState.Error("Host or username is empty")
            return
        }

        initSystemProxySelector()
        currentConfigKey = configKey

        if (proxyUser.isNotBlank() && proxyPass.isNotBlank()) {
            System.setProperty("java.net.socks.username", proxyUser)
            System.setProperty("java.net.socks.password", proxyPass)
            Authenticator.setDefault(
                object : Authenticator() {
                    override fun getPasswordAuthentication(): PasswordAuthentication {
                        return PasswordAuthentication(proxyUser, proxyPass.toCharArray())
                    }
                }
            )
        }

        tunnelJob = scope.launch {
            _state.value = TunnelState.Connecting
            Log.i(TAG, "Starting SSH tunnel to $username@$host:$port (remote target: $remoteTargetPort)")

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
                    currentSession.serverAliveInterval = 15
                    currentSession.serverAliveCountMax = 4
                    currentSession.timeout = 20000

                    currentSession.userInfo = object : UserInfo {
                        override fun getPassphrase(): String? = null
                        override fun getPassword(): String = password ?: ""
                        override fun promptPassword(message: String?): Boolean = true
                        override fun promptPassphrase(message: String?): Boolean = true
                        override fun promptYesNo(message: String?): Boolean = true
                        override fun showMessage(message: String?) {
                            Log.d(TAG, "JSCH showMessage: $message")
                        }
                    }

                    Log.i(TAG, "Connecting JSch session...")
                    currentSession.connect(20000)
                    Log.i(TAG, "JSch session connected! Establishing port forwarding to $remoteTargetPort...")

                    val localPort = currentSession.setPortForwardingL("127.0.0.1", 0, "127.0.0.1", remoteTargetPort)
                    session = currentSession

                    GlobalProxySelector.activeProxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", localPort))
                    _state.value = TunnelState.Connected(host, port, localPort)
                    Log.i(TAG, "SSH tunnel ready! Local SOCKS on 127.0.0.1:$localPort -> remote 127.0.0.1:$remoteTargetPort")

                    while (isActive && currentSession.isConnected) {
                        delay(3000)
                    }
                    Log.w(TAG, "Session disconnected or loop exited (isActive=$isActive, isConnected=${currentSession.isConnected})")
                } catch (e: Throwable) {
                    if (e is kotlinx.coroutines.CancellationException) {
                        Log.i(TAG, "SSH Tunnel job cancelled")
                        throw e
                    }
                    Log.e(TAG, "SSH Tunnel error: ${e.message}", e)
                    _state.value = TunnelState.Error(e.message ?: "Connection failed")
                } finally {
                    try {
                        currentSession?.disconnect()
                    } catch (_: Throwable) {}
                    if (session === currentSession) {
                        session = null
                        GlobalProxySelector.activeProxy = null
                    }
                }

                if (!isActive) break
                Log.i(TAG, "Will retry SSH connection in 5 seconds...")
                delay(5000)
            }
        }
    }

    @Synchronized
    fun stop() {
        tunnelJob?.cancel()
        tunnelJob = null
        currentConfigKey = null
        try {
            session?.disconnect()
        } catch (_: Throwable) {}
        session = null
        GlobalProxySelector.activeProxy = null
        _state.value = TunnelState.Disconnected
        Log.i(TAG, "SSH Tunnel stopped")
    }
}
