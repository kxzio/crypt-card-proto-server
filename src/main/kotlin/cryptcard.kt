import com.southernstorm.noise.protocol.HandshakeState
import com.southernstorm.noise.protocol.CipherStatePair
import kotlinx.coroutines.*
import java.io.*
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val MAX_MESSAGE_SIZE = 64 * 1024
private const val SESSION_ID_BYTES = 16
private const val SESSION_TTL_MS = 10 * 60_000L
private const val MAX_HANDSHAKES_PER_IP = 5
private const val MAX_MSGS_PER_SESSION = 1000
private val secureRandom = SecureRandom()
private val AES_KEY_FILE = File("server_key.aes")
private val PRIV_KEY_FILE = File("server_ed.key")
private val PUB_KEY_FILE = File("server_ed.pub")

private fun generateAESKey(): SecretKey {
    val bytes = ByteArray(32)
    secureRandom.nextBytes(bytes)
    return SecretKeySpec(bytes, "AES")
}

private fun encryptAESGCM(data: ByteArray, key: SecretKey): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val iv = ByteArray(12).apply { secureRandom.nextBytes(this) }
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    return iv + cipher.doFinal(data)
}

private fun decryptAESGCM(data: ByteArray, key: SecretKey): ByteArray {
    val iv = data.copyOfRange(0, 12)
    val ct = data.copyOfRange(12, data.size)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
    return cipher.doFinal(ct)
}

fun loadOrCreateAESKey(): SecretKey {
    return if (AES_KEY_FILE.exists() && AES_KEY_FILE.length() == 32L) {
        SecretKeySpec(AES_KEY_FILE.readBytes(), "AES")
    } else {
        val key = generateAESKey()
        AES_KEY_FILE.writeBytes(key.encoded)
        key
    }
}

fun loadOrCreateEd25519KeyPair(aesKey: SecretKey): Pair<PublicKey, PrivateKey> {
    if (PRIV_KEY_FILE.exists() && PUB_KEY_FILE.exists()) {
        val priv = PKCS8EncodedKeySpec(decryptAESGCM(PRIV_KEY_FILE.readBytes(), aesKey))
        val pub = X509EncodedKeySpec(PUB_KEY_FILE.readBytes())
        val kf = KeyFactory.getInstance("Ed25519")
        return Pair(kf.generatePublic(pub), kf.generatePrivate(priv))
    }
    val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    PRIV_KEY_FILE.writeBytes(encryptAESGCM(kp.private.encoded, aesKey))
    PUB_KEY_FILE.writeBytes(kp.public.encoded)
    return Pair(kp.public, kp.private)
}

fun signData(data: ByteArray, priv: PrivateKey): ByteArray {
    val sig = Signature.getInstance("Ed25519")
    sig.initSign(priv)
    sig.update(data)
    return sig.sign()
}

fun verifySignature(data: ByteArray, sigBytes: ByteArray, pub: PublicKey): Boolean {
    val sig = Signature.getInstance("Ed25519")
    sig.initVerify(pub)
    sig.update(data)
    return sig.verify(sigBytes)
}

class NoiseSocket(private val socket: Socket, private val isInitiator: Boolean) {
    private val input = socket.getInputStream()
    private val output = socket.getOutputStream()
    val handshake = HandshakeState(
        "Noise_XX_25519_ChaChaPoly_SHA256",
        if (isInitiator) HandshakeState.INITIATOR else HandshakeState.RESPONDER
    )
    private lateinit var pair: CipherStatePair
    lateinit var sessionId: ByteArray
        private set
    private val transcript = ByteArrayOutputStream()
    private val sendSeq = AtomicLong(0)
    private val lastSeqPerSession = ConcurrentHashMap<String, Long>()
    private var handshakeCompleted = false
    var msgCount = 0

    suspend fun initHandshake(serverSignedStatic: ByteArray? = null, serverPubEd: PublicKey? = null) = withContext(Dispatchers.IO) {
        if (handshakeCompleted) throw IllegalStateException("Handshake already completed")
        if (handshake.needsLocalKeyPair()) handshake.localKeyPair.generateKeyPair()
        handshake.start()
        val buf = ByteArray(65536)

        if (isInitiator) {
            val len1 = handshake.writeMessage(buf, 0, null, 0, 0)
            sendBytesWithLength(buf, 0, len1)
            transcript.write(buf, 0, len1)

            val (msg2, l2) = receiveLengthPrefixed()
            handshake.readMessage(msg2, 0, l2, ByteArray(0), 0)
            transcript.write(msg2, 0, l2)

            val len3 = handshake.writeMessage(buf, 0, null, 0, 0)
            sendBytesWithLength(buf, 0, len3)
            transcript.write(buf, 0, len3)

            if (serverSignedStatic != null && serverPubEd != null) {
                val signedKey = serverSignedStatic.copyOfRange(0, 32)
                val signature = serverSignedStatic.copyOfRange(32, serverSignedStatic.size)
                if (!verifySignature(signedKey, signature, serverPubEd)) throw SecurityException("Server signature invalid")
            }
        } else {
            val (msg1, l1) = receiveLengthPrefixed()
            handshake.readMessage(msg1, 0, l1, ByteArray(0), 0)
            transcript.write(msg1, 0, l1)

            val len2 = handshake.writeMessage(buf, 0, null, 0, 0)
            sendBytesWithLength(buf, 0, len2)
            transcript.write(buf, 0, len2)

            val (msg3, l3) = receiveLengthPrefixed()
            handshake.readMessage(msg3, 0, l3, ByteArray(0), 0)
            transcript.write(msg3, 0, l3)
        }

        pair = handshake.split()
        val h = handshake.handshakeHash
        sessionId = if (h != null && h.size >= SESSION_ID_BYTES) h.copyOfRange(0, SESSION_ID_BYTES)
        else MessageDigest.getInstance("SHA-256").digest(transcript.toByteArray()).copyOfRange(0, SESSION_ID_BYTES)
        handshakeCompleted = true
    }

    suspend fun send(plaintext: ByteArray) = withContext(Dispatchers.IO) {
        ensurePair()
        if (plaintext.size > MAX_MESSAGE_SIZE) throw IllegalArgumentException("Message too large")
        if (++msgCount > MAX_MSGS_PER_SESSION) throw SecurityException("Session message limit exceeded")
        val seq = sendSeq.getAndIncrement()
        val seqBytes = ByteBuffer.allocate(8).putLong(seq).array()
        val aad = sessionId + seqBytes
        val ctBuf = ByteArray(plaintext.size + pair.sender.getMACLength())
        val ctLen = pair.sender.encryptWithAd(aad, plaintext, 0, ctBuf, 0, plaintext.size)
        val framed = seqBytes + ctBuf.copyOf(ctLen)
        sendBytesWithLength(framed, 0, framed.size)
    }

    suspend fun receive(): ByteArray = withContext(Dispatchers.IO) {
        ensurePair()
        val (payload, len) = receiveLengthPrefixed()
        val seqBytes = payload.copyOfRange(0, 8)
        val seq = ByteBuffer.wrap(seqBytes).long
        val ct = payload.copyOfRange(8, len)
        val aad = sessionId + seqBytes
        val plainBuf = ByteArray(ct.size)
        val ptLen = pair.receiver.decryptWithAd(aad, ct, 0, plainBuf, 0, ct.size)
        val sessionKey = Base64.getEncoder().encodeToString(sessionId)
        val lastSeq = lastSeqPerSession.getOrDefault(sessionKey, -1L)
        if (seq <= lastSeq) throw SecurityException("Replay detected")
        lastSeqPerSession[sessionKey] = seq
        if (++msgCount > MAX_MSGS_PER_SESSION) throw SecurityException("Session message limit exceeded")
        plainBuf.copyOf(ptLen)
    }

    fun close() {
        try { if (this::pair.isInitialized) pair.destroy() } catch (_: Exception) {}
        try { handshake.destroy() } catch (_: Exception) {}
        try { socket.close() } catch (_: Exception) {}
    }

    private fun ensurePair() { if (!this::pair.isInitialized) throw IllegalStateException("Handshake not completed") }

    private fun sendBytesWithLength(buf: ByteArray, offset: Int, len: Int) {
        val lenPrefix = ByteBuffer.allocate(4).putInt(len).array()
        output.write(lenPrefix)
        output.write(buf, offset, len)
        output.flush()
    }

    private fun receiveLengthPrefixed(): Pair<ByteArray, Int> {
        val lenPrefix = readExact(4)
        val len = ByteBuffer.wrap(lenPrefix).int
        if (len > MAX_MESSAGE_SIZE) throw SecurityException("Message exceeds maximum size")
        val data = readExact(len)
        return Pair(data, len)
    }

    private fun readExact(len: Int): ByteArray {
        val buf = ByteArray(len)
        var read = 0
        while (read < len) {
            val r = input.read(buf, read, len - read)
            if (r == -1) throw EOFException("Stream closed during readExact")
            read += r
        }
        return buf
    }
}

data class Session(val ns: NoiseSocket, val createdAt: Long = System.currentTimeMillis(), val ip: String)
private val activeSessions = ConcurrentHashMap<String, Session>()
private val handshakeCountsPerIP = ConcurrentHashMap<String, AtomicLong>()

fun cleanupSessions() {
    val now = System.currentTimeMillis()
    activeSessions.entries.removeIf { now - it.value.createdAt > SESSION_TTL_MS }
    handshakeCountsPerIP.entries.removeIf { it.value.get() == 0L }
}

suspend fun runServerAsync(port: Int, serverPrivEd: PrivateKey) = coroutineScope {
    val server = ServerSocket(port)
    println("[Server] listening $port")

    while (true) {
        val client = server.accept()
        client.soTimeout = 15_000
        val clientIP = client.inetAddress.hostAddress
        val count = handshakeCountsPerIP.computeIfAbsent(clientIP) { AtomicLong(0) }
        if (count.incrementAndGet() > MAX_HANDSHAKES_PER_IP) {
            println("[Server] Too many handshakes from $clientIP")
            client.close()
            continue
        }

        launch {
            try {
                val ns = NoiseSocket(client, false)
                val dhPub = ByteArray(ns.handshake.localKeyPair.publicKeyLength)
                ns.handshake.localKeyPair.getPublicKey(dhPub, 0)
                val signature = signData(dhPub, serverPrivEd)
                val signedStatic = dhPub + signature

                ns.initHandshake(serverSignedStatic = signedStatic)
                val sid = Base64.getEncoder().encodeToString(ns.sessionId)
                activeSessions[sid] = Session(ns, ip = clientIP)
                println("[Server] handshake complete, sessionId=$sid")

                val msg = ns.receive()
                println("[Server] got: ${String(msg)}")
                ns.send("pong-from-server".toByteArray())
            } catch (e: Throwable) {
                println("[Server] error: ${e.message}")
            } finally {
                try { client.close() } catch (_: Exception) {}
                count.decrementAndGet()
            }
            cleanupSessions()
        }
    }
}

suspend fun runClientAsync(host: String, port: Int, serverPubEd: PublicKey) = coroutineScope {
    val socket = Socket(host, port)
    socket.soTimeout = 15_000
    val ns = NoiseSocket(socket, true)
    ns.initHandshake(serverPubEd = serverPubEd)
    println("[Client] sending hello")
    ns.send("hello-server".toByteArray())
    val reply = ns.receive()
    println("[Client] reply: ${String(reply)}")
    ns.close()
}

fun main() = runBlocking {

    val aesKey = loadOrCreateAESKey()
    val (serverPubEd, serverPrivEd) = loadOrCreateEd25519KeyPair(aesKey)

    val serverJob = launch(Dispatchers.IO) { runServerAsync(9000, serverPrivEd) }

    delay(500)

    runClientAsync("localhost", 9000, serverPubEd)

    println("Client finished communication")
    serverJob.join()
}