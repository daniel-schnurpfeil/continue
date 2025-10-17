package com.github.continuedev.continueintellijextension.services


import com.intellij.credentialStore.CredentialAttributes
import com.intellij.credentialStore.Credentials
import com.intellij.ide.BrowserUtil
import com.intellij.ide.passwordSafe.PasswordSafe
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.intellij.openapi.project.Project
import com.github.continuedev.continueintellijextension.McpServerAuth
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*

@Service(Service.Level.PROJECT)
class McpOAuthService(private val project: Project) {

    private val httpClient = HttpClient(CIO) {
        install(ContentNegotiation) {
            json(Json {
                ignoreUnknownKeys = true
                isLenient = true
            })
        }
    }

    @Serializable
    data class TokenResponse(
        val access_token: String,
        val token_type: String? = null,
        val expires_in: Int? = null,
        val refresh_token: String? = null,
        val scope: String? = null
    )

    companion object {
        fun getInstance(project: Project): McpOAuthService = project.service()

        private fun generateCodeVerifier(): String {
            val bytes = ByteArray(32)
            SecureRandom().nextBytes(bytes)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        }

        private fun generateCodeChallenge(verifier: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(verifier.toByteArray(StandardCharsets.UTF_8))
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
        }
    }

    /**
     * Initiates OAuth2 flow for MCP server
     */
    suspend fun authenticate(
        serverName: String,
        authConfig: McpServerAuth
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            val state = UUID.randomUUID().toString()
            val codeVerifier = if (authConfig.usePKCE == true) generateCodeVerifier() else null
            val codeChallenge = codeVerifier?.let { generateCodeChallenge(it) }

            // Store state and verifier temporarily
            val stateKey = "mcp_oauth_state_$serverName"
            val verifierKey = "mcp_oauth_verifier_$serverName"

            PasswordSafe.instance.setPassword(
                CredentialAttributes(stateKey),
                state
            )

            codeVerifier?.let {
                PasswordSafe.instance.setPassword(
                    CredentialAttributes(verifierKey),
                    it
                )
            }

            // Build authorization URL
            val authUrl = buildAuthorizationUrl(authConfig, state, codeChallenge)

            // Start local server to receive callback
            val authorizationCode = CompletableDeferred<String>()
            val server = startCallbackServer(
                authConfig.redirectUri ?: "http://localhost:3000",
                state,
                authorizationCode
            )

            // Open browser for user authentication
            BrowserUtil.browse(authUrl)

            // Wait for callback with timeout
            val code = withTimeout(300_000) { // 5 minutes timeout
                authorizationCode.await()
            }

            server.stop(1000, 2000)

            // Exchange code for token
            val token = exchangeCodeForToken(
                authConfig,
                code,
                codeVerifier
            )

            // Store token securely
            storeToken(serverName, token)

            // Cleanup temporary state
            PasswordSafe.instance.setPassword(CredentialAttributes(stateKey), null)
            PasswordSafe.instance.setPassword(CredentialAttributes(verifierKey), null)

            Result.success(token.access_token)

        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Retrieves stored access token for MCP server
     */
    fun getAccessToken(serverName: String): String? {
        val credentials = PasswordSafe.instance.get(
            CredentialAttributes("mcp_oauth_token_$serverName")
        )
        return credentials?.getPasswordAsString()
    }

    /**
     * Refreshes the access token if refresh token is available
     */
    suspend fun refreshToken(
        serverName: String,
        authConfig: McpServerAuth
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            val refreshToken = getRefreshToken(serverName)
                ?: return@withContext Result.failure(Exception("No refresh token available"))

            val tokenUrl = authConfig.tokenUrl
                ?: return@withContext Result.failure(Exception("Token URL not configured"))

            val response: TokenResponse = httpClient.submitForm(
                url = tokenUrl,
                formParameters = parameters {
                    append("grant_type", "refresh_token")
                    append("refresh_token", refreshToken)
                    append("client_id", authConfig.clientId ?: "")
                    authConfig.clientSecret?.let { append("client_secret", it) }
                }
            ).body()

            storeToken(serverName, response)
            Result.success(response.access_token)

        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun buildAuthorizationUrl(
        authConfig: McpServerAuth,
        state: String,
        codeChallenge: String?
    ): String {
        val params = mutableMapOf(
            "response_type" to "code",
            "client_id" to (authConfig.clientId ?: ""),
            "redirect_uri" to (authConfig.redirectUri ?: "http://localhost:3000"),
            "state" to state
        )

        authConfig.scopes?.let {
            params["scope"] = it.joinToString(" ")
        }

        if (authConfig.usePKCE == true && codeChallenge != null) {
            params["code_challenge"] = codeChallenge
            params["code_challenge_method"] = "S256"
        }

        val queryString = params.entries.joinToString("&") { (key, value) ->
            "$key=${URLEncoder.encode(value, StandardCharsets.UTF_8.toString())}"
        }

        return "${authConfig.authorizationUrl}?$queryString"
    }

    private fun startCallbackServer(
        redirectUri: String,
        expectedState: String,
        authorizationCode: CompletableDeferred<String>
    ): NettyApplicationEngine {
        val uri = java.net.URI(redirectUri)
        val port = if (uri.port > 0) uri.port else 3000

        return embeddedServer(Netty, port = port) {
            routing {
                get(uri.path.takeIf { it.isNotEmpty() } ?: "/") {
                    val code = call.request.queryParameters["code"]
                    val state = call.request.queryParameters["state"]
                    val error = call.request.queryParameters["error"]

                    when {
                        error != null -> {
                            call.respondText(
                                "Authentication failed: $error",
                                status = HttpStatusCode.BadRequest
                            )
                            authorizationCode.completeExceptionally(
                                Exception("OAuth error: $error")
                            )
                        }
                        state != expectedState -> {
                            call.respondText(
                                "Invalid state parameter",
                                status = HttpStatusCode.BadRequest
                            )
                            authorizationCode.completeExceptionally(
                                Exception("State mismatch")
                            )
                        }
                        code != null -> {
                            call.respondText(
                                "Authentication successful! You can close this window.",
                                status = HttpStatusCode.OK
                            )
                            authorizationCode.complete(code)
                        }
                        else -> {
                            call.respondText(
                                "Missing authorization code",
                                status = HttpStatusCode.BadRequest
                            )
                            authorizationCode.completeExceptionally(
                                Exception("Missing code parameter")
                            )
                        }
                    }
                }
            }
        }.start(wait = false)
    }

    private suspend fun exchangeCodeForToken(
        authConfig: McpServerAuth,
        code: String,
        codeVerifier: String?
    ): TokenResponse {
        val tokenUrl = authConfig.tokenUrl
            ?: throw Exception("Token URL not configured")

        return httpClient.submitForm(
            url = tokenUrl,
            formParameters = parameters {
                append("grant_type", "authorization_code")
                append("code", code)
                append("redirect_uri", authConfig.redirectUri ?: "http://localhost:3000")
                append("client_id", authConfig.clientId ?: "")
                authConfig.clientSecret?.let { append("client_secret", it) }
                codeVerifier?.let { append("code_verifier", it) }
            }
        ).body()
    }

    private fun storeToken(serverName: String, tokenResponse: TokenResponse) {
        // Store access token
        PasswordSafe.instance.set(
            CredentialAttributes("mcp_oauth_token_$serverName"),
            Credentials("", tokenResponse.access_token)
        )

        // Store refresh token if available
        tokenResponse.refresh_token?.let { refreshToken ->
            PasswordSafe.instance.set(
                CredentialAttributes("mcp_oauth_refresh_token_$serverName"),
                Credentials("", refreshToken)
            )
        }
    }

    private fun getRefreshToken(serverName: String): String? {
        return PasswordSafe.instance.get(
            CredentialAttributes("mcp_oauth_refresh_token_$serverName")
        )?.getPasswordAsString()
    }

    fun clearTokens(serverName: String) {
        PasswordSafe.instance.setPassword(
            CredentialAttributes("mcp_oauth_token_$serverName"),
            null
        )
        PasswordSafe.instance.setPassword(
            CredentialAttributes("mcp_oauth_refresh_token_$serverName"),
            null
        )
    }
}