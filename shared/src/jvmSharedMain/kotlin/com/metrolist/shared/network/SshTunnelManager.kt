package com.metrolist.shared.network

import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.UserInfo
import com.metrolist.shared.settings.Settings
import kotlinx.coroutines.CancellationException
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

private object SshLog {
    private val logMethodI by lazy { runCatching { Class.forName("android.util.Log").getMethod("i", String::class.java, String::class.java) }.getOrNull() }
    private val logMethodD by lazy { runCatching { Class.forName("android.util.Log").getMethod("d", String::class.java, String::class.java) }.getOrNull() }
    private val logMethodW by lazy { runCatching { Class.forName("android.util.Log").getMethod("w", String::class.java, String::class.java) }.getOrNull() }
    private val logMethodE by lazy { runCatching { Class.forName("android.util.Log").getMethod("e", String::class.java, String::class.java, Throwable::class.java) }.getOrNull() }

    fun i(tag: String, msg: String) {
        logMethodI?.invoke(null, tag, msg) ?: println("[$tag] $msg")
    }
    fun d(tag: String, msg: String) {
        logMethodD?.invoke(null, tag, msg) ?: Unit
    }
    fun w(tag: String, msg: String) {
        logMethodW?.invoke(null, tag, msg) ?: println("[$tag WARN] $msg")
    }
    fun e(tag: String, msg: String, tr: Throwable? = null) {
        logMethodE?.invoke(null, tag, msg, tr) ?: run {
            System.err.println("[$tag ERROR] $msg")
            tr?.printStackTrace()
        }
    }
}

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
                    SshLog.d(TAG, "[JSCH $level] $message")
                }
            })
        } catch (e: Throwable) {
            SshLog.e(TAG, "Failed to set JSch logger", e)
        }
    }

    fun initSystemProxySelector() {
        try {
            ProxySelector.setDefault(GlobalProxySelector)
            Authenticator.setDefault(
                object : Authenticator() {
                    override fun getPasswordAuthentication(): PasswordAuthentication? {
                        val s = Settings.shared
                        if (s.sshTunnelProxyUser.isNotBlank()) {
                            return PasswordAuthentication(s.sshTunnelProxyUser, s.sshTunnelProxyPassword.toCharArray())
                        }
                        return null
                    }
                }
            )
            SshLog.i(TAG, "GlobalProxySelector and Authenticator installed as system default")
        } catch (e: Exception) {
            SshLog.e(TAG, "Failed to set default ProxySelector", e)
        }
    }

    @Synchronized
    fun startFromSettings() {
        val settings = Settings.shared
        if (!settings.sshTunnelEnabled) {
            SshLog.i(TAG, "SSH Tunnel disabled in settings")
            stop()
            return
        }
        val configKey = "${settings.sshTunnelHost}:${settings.sshTunnelPort}:${settings.sshTunnelUser}:${settings.sshTunnelPassword}:${settings.sshTunnelRemotePort}:${settings.sshTunnelProxyUser}:${settings.sshTunnelProxyPassword}"
        if (session?.isConnected == true && currentConfigKey == configKey) {
            SshLog.i(TAG, "SSH tunnel already connected with current config")
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
            SshLog.i(TAG, "Tunnel already active for $username@$host:$port")
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
            SshLog.i(TAG, "Starting SSH tunnel to $username@$host:$port (remote target: $remoteTargetPort)")

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
                            SshLog.d(TAG, "JSCH showMessage: $message")
                        }
                    }

                    SshLog.i(TAG, "Connecting JSch session...")
                    currentSession.connect(20000)
                    SshLog.i(TAG, "JSch session connected! Establishing port forwarding to $remoteTargetPort...")

                    val localPort = currentSession.setPortForwardingL("127.0.0.1", 0, "127.0.0.1", remoteTargetPort)
                    session = currentSession

                    GlobalProxySelector.activeProxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", localPort))
                    _state.value = TunnelState.Connected(host, port, localPort)
                    SshLog.i(TAG, "SSH tunnel ready! Local SOCKS on 127.0.0.1:$localPort -> remote 127.0.0.1:$remoteTargetPort")

                    while (isActive && currentSession.isConnected) {
                        delay(3000)
                    }
                    SshLog.w(TAG, "Session disconnected or loop exited (isActive=$isActive, isConnected=${currentSession.isConnected})")
                } catch (e: Throwable) {
                    if (e is CancellationException) {
                        SshLog.i(TAG, "SSH Tunnel job cancelled")
                        throw e
                    }
                    SshLog.e(TAG, "SSH Tunnel error: ${e.message}", e)
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
                SshLog.i(TAG, "Will retry SSH connection in 5 seconds...")
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
        SshLog.i(TAG, "SSH Tunnel stopped")
    }
}
