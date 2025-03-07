package za.co.britehouse.flutter_microsoft_authentication

import android.app.Activity
import android.app.ActivityManager
import android.content.Context
import android.util.Log
import com.microsoft.identity.client.*
import com.microsoft.identity.client.exception.MsalClientException
import com.microsoft.identity.client.exception.MsalException
import com.microsoft.identity.client.exception.MsalServiceException
import com.microsoft.identity.client.exception.MsalUiRequiredException
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.File
import java.io.FileOutputStream
import java.io.IOException


class FlutterMicrosoftAuthenticationPlugin : FlutterPlugin, ActivityAware, MethodCallHandler {
    private lateinit var channel: MethodChannel

    private var mSingleAccountApp: ISingleAccountPublicClientApplication? = null
    private var binding: FlutterPlugin.FlutterPluginBinding? = null
    private var activity: Activity? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        this.binding = binding
        this.channel = MethodChannel(binding.binaryMessenger, "flutter_microsoft_authentication")
        this.channel.setMethodCallHandler(this)
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        this.activity = binding.activity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        this.activity = binding.activity
    }

    override fun onDetachedFromActivity() {
        this.activity = null
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        this.binding = null
        this.activity = null
        this.channel.setMethodCallHandler(null)
    }

    companion object {
        private const val TAG = "FMAuthPlugin"
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        val scopesArg: ArrayList<String>? = call.argument("kScopes")
        val scopes: Array<String>? = scopesArg?.toTypedArray()
        val authority: String? = call.argument("kAuthority")
        val configPath: String? = call.argument("configPath")
        val shouldLoginAutomatically: Boolean? = call.argument("shouldLoginAutomatically")

        when (call.method) {
            "init" -> {
                if (configPath == null) {
                    Log.d(TAG, "no config")
                    result.error("NO_CONFIG", "Call must include a config file path", null)
                    return
                }
                initPlugin(configPath, result)
            }
            "acquireTokenInteractively" -> {
                if (scopes == null) {
                    Log.d(TAG, "no scope")
                    result.error("NO_SCOPE", "Call must include a scope", null)
                    return
                }
                acquireTokenInteractively(scopes, result, shouldLoginAutomatically)
            }
            "acquireTokenSilently" -> {
                if (scopes == null) {
                    Log.d(TAG, "no scope")
                    result.error("NO_SCOPE", "Call must include a scope", null)
                    return
                }
                if (authority == null) {
                    Log.d(TAG, "error no authority")
                    result.error("NO_AUTHORITY", "Call must include an authority", null)
                    return
                }
                acquireTokenSilently(scopes, authority, result)
            }
            "refreshToken" -> {
                if (scopes == null) {
                    Log.d(TAG, "no scope")
                    result.error("NO_SCOPE", "Call must include a scope", null)
                    return
                }
                if (authority == null) {
                    Log.d(TAG, "error no authority")
                    result.error("NO_AUTHORITY", "Call must include an authority", null)
                    return
                }
                refreshToken(scopes, authority, result)
            }
            "signOut" -> signOut(result)
            else -> result.notImplemented()
        }
    }

    @Throws(IOException::class)
    private fun getConfigFile(path: String, binding: FlutterPlugin.FlutterPluginBinding): File {
        val key: String = binding.flutterAssets.getAssetFilePathByName(path)
        val configFile = File(binding.applicationContext.cacheDir, "config.json")

        try {
            val assetManager = binding.applicationContext.assets

            val inputStream = assetManager.open(key)
            val outputStream = FileOutputStream(configFile)
            try {
                Log.d(TAG, "File exists: ${configFile.exists()}")
                if (configFile.exists()) {
                    outputStream.write("".toByteArray())
                }
                inputStream.copyTo(outputStream)
            } finally {
                inputStream.close()
                outputStream.close()
            }
            return configFile

        } catch (e: IOException) {
            throw IOException("Could not open config file", e)
        }
    }

    private fun initPlugin(assetPath: String, result: Result) {
        binding?.let {
            try {
                val configFile = getConfigFile(assetPath, it)
                val context: Context = it.applicationContext

                PublicClientApplication.createSingleAccountPublicClientApplication(context,
                    configFile,
                    object : IPublicClientApplication.ISingleAccountApplicationCreatedListener {
                        override fun onCreated(application: ISingleAccountPublicClientApplication) {
                            /**
                             * This app assumes that the app is only going to support one account.
                             * This requires "account_mode" : "SINGLE" in the config json file.
                             */
                            Log.d(TAG, "INITIALIZED")
                            mSingleAccountApp = application
                            result.success(null)
                        }

                        override fun onError(exception: MsalException) {
                            Log.e(TAG, "Error creating application: ${exception.message}")
                            result.error(
                                exception.errorCode ?: "AccountInitError",
                                exception.message ?: "Failed to initialize account",
                                null
                            )
                        }
                    })
            } catch (e: IOException) {
                Log.e(TAG, "Error reading config file: ${e.message}")
                result.error("ConfigFileError", e.message, null)
            } catch (e: Exception) {
                Log.e(TAG, "Unexpected error during initialization: ${e.message}")
                result.error("InitializationError", e.message, null)
            }
        } ?: result.error(
            "FlutterPluginException",
            "Flutter plugin binding is null, cannot continue configuration",
            null
        )
    }

    private fun acquireTokenInteractively(
        scopes: Array<String>,
        result: Result,
        shouldLoginAutomatically: Boolean?
    ) {
        if (mSingleAccountApp == null) {
            result.error("MsalClientException", "Account not initialized", null)
            return
        }

        if (activity == null) {
            result.error("ActivityError", "Activity is null, cannot continue with interactive authentication", null)
            return
        }

        try {
            val parameters = SignInParameters.builder()
                .withScopes(scopes.toList())
                .withActivity(activity!!)
                .withCallback(getAuthInteractiveCallback(result))
                .withPrompt(if (shouldLoginAutomatically == true) Prompt.SELECT_ACCOUNT else Prompt.LOGIN)
                .build()

            mSingleAccountApp!!.signIn(parameters)
        } catch (e: Exception) {
            Log.e(TAG, "Error during interactive authentication: ${e.message}")
            result.error("InteractiveAuthError", e.message, null)
        }
    }

    private fun acquireTokenSilently(scopes: Array<String>, authority: String, result: Result) {
        if (mSingleAccountApp == null) {
            result.error("MsalClientException", "Account not initialized", null)
            return
        }

        try {
            mSingleAccountApp!!.getCurrentAccountAsync(object :
                ISingleAccountPublicClientApplication.CurrentAccountCallback {
                override fun onAccountLoaded(activeAccount: IAccount?) {
                    if (activeAccount == null) {
                        result.error("MsalClientException", "No active account found", null)
                        return
                    }

                    try {
                        val parameters = AcquireTokenSilentParameters.Builder()
                            .withScopes(scopes.toList())
                            .fromAuthority(authority)
                            .forAccount(activeAccount)
                            .withCallback(getAuthSilentCallback(result))
                            .build()

                        mSingleAccountApp!!.acquireTokenSilentAsync(parameters)
                    } catch (e: Exception) {
                        Log.e(TAG, "Error creating silent parameters: ${e.message}")
                        result.error("SilentParametersError", e.message, null)
                    }
                }

                override fun onAccountChanged(priorAccount: IAccount?, currentAccount: IAccount?) {
                    if (currentAccount == null) {
                        // If there is no current account, it indicates the user has been signed out or account changed.
                        signOut(result)
                    } else {
                        // Handle account change if needed
                        result.success(mapOf(
                            "status" to "account_changed",
                            "user ID" to currentAccount.id
                        ))
                    }
                }

                override fun onError(exception: MsalException) {
                    Log.e(TAG, "Error getting current account: ${exception.message}")
                    result.error(
                        exception.errorCode,
                        "Failed to get current account: ${exception.message}",
                        null
                    )
                }
            })
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error during silent authentication: ${e.message}")
            result.error("SilentAuthError", e.message, null)
        }
    }

    /**
     * Refreshes the access token silently using the refresh token
     * This method should be called when the current access token is about to expire
     *
     * @param scopes Array of scopes to request
     * @param authority The authority URL
     * @param result The Flutter result callback
     */
    private fun refreshToken(scopes: Array<String>, authority: String, result: Result) {
        if (mSingleAccountApp == null) {
            result.error("MsalClientException", "Account not initialized", null)
            return
        }

        try {
            // Get the current account
            mSingleAccountApp!!.getCurrentAccountAsync(object :
                ISingleAccountPublicClientApplication.CurrentAccountCallback {
                override fun onAccountLoaded(activeAccount: IAccount?) {
                    if (activeAccount == null) {
                        result.error("MsalClientException", "No active account found", null)
                        return
                    }

                    Log.d(TAG, "Refreshing token for account: ${activeAccount.id}")

                    try {
                        // Force token refresh by setting forceRefresh to true
                        val parameters = AcquireTokenSilentParameters.Builder()
                            .withScopes(scopes.toList())
                            .fromAuthority(authority)
                            .forAccount(activeAccount)
                            .forceRefresh(true) // This forces MSAL to bypass the cache and get a new token
                            .withCallback(object : AuthenticationCallback {
                                override fun onSuccess(authenticationResult: IAuthenticationResult) {
                                    Log.d(TAG, "Token refreshed successfully")
                                    result.success(
                                        hashMapOf(
                                            "ID token" to authenticationResult.account.idToken,
                                            "access token" to authenticationResult.accessToken,
                                            "user ID" to authenticationResult.account.id,
                                            "expires_on" to authenticationResult.expiresOn.time
                                        )
                                    )
                                }

                                override fun onError(exception: MsalException) {
                                    Log.e(TAG, "Token refresh failed: ${exception.message}")

                                    when (exception) {
                                        is MsalClientException -> {
                                            result.error(
                                                exception.errorCode ?: "MsalClientException",
                                                "Token refresh failed: ${exception.message}",
                                                null
                                            )
                                        }
                                        is MsalServiceException -> {
                                            result.error(
                                                exception.errorCode ?: "MsalServiceException",
                                                "Token refresh failed: ${exception.message}",
                                                null
                                            )
                                        }
                                        is MsalUiRequiredException -> {
                                            // Token cannot be refreshed silently, interactive auth required
                                            result.error(
                                                "InteractiveAuthRequired",
                                                "Token cannot be refreshed silently, interactive authentication required",
                                                null
                                            )
                                        }
                                        else -> result.error(
                                            exception.errorCode ?: "Msal",
                                            "Token refresh failed: ${exception.message}",
                                            null
                                        )
                                    }
                                }

                                override fun onCancel() {
                                    Log.d(TAG, "Token refresh canceled")
                                    result.error("MsalUserCancel", "Token refresh canceled", null)
                                }
                            })
                            .build()

                        // Execute the token refresh
                        mSingleAccountApp!!.acquireTokenSilentAsync(parameters)
                    } catch (e: Exception) {
                        Log.e(TAG, "Error creating refresh parameters: ${e.message}")
                        result.error("RefreshParametersError", e.message, null)
                    }
                }

                override fun onAccountChanged(priorAccount: IAccount?, currentAccount: IAccount?) {
                    if (currentAccount == null) {
                        result.error("MsalClientException", "Account changed during refresh", null)
                    } else {
                        // Handle account change
                        Log.d(TAG, "Account changed during refresh operation")
                        // Retry with new account
                        refreshToken(scopes, authority, result)
                    }
                }

                override fun onError(exception: MsalException) {
                    Log.e(TAG, "Error getting current account for token refresh: ${exception.message}")
                    result.error(
                        "MsalClientException",
                        "Failed to get current account for token refresh: ${exception.message}",
                        null
                    )
                }
            })
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error during token refresh: ${e.message}")
            result.error("RefreshTokenError", e.message, null)
        }
    }

    private fun signOut(result: Result) {
        if (mSingleAccountApp == null) {
            result.error("MsalClientException", "Account not initialized", null)
            return
        }

        try {
            mSingleAccountApp!!.signOut(object : ISingleAccountPublicClientApplication.SignOutCallback {
                override fun onSignOut() {
                    Log.d(TAG, "Sign out successful")
                    result.success(null)
                }

                override fun onError(exception: MsalException) {
                    Log.e(TAG, "Sign out failed: ${exception.message}")
                    result.error(
                        exception.errorCode ?: "SIGN_OUT",
                        "Sign out failed: ${exception.message}",
                        null
                    )
                }
            })
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error during sign out: ${e.message}")
            result.error("SignOutError", e.message, null)
        }
    }

    private fun getAuthInteractiveCallback(result: Result): AuthenticationCallback {
        return object : AuthenticationCallback {
            override fun onSuccess(authenticationResult: IAuthenticationResult) {
                Log.d(TAG, "Successfully authenticated")
                result.success(
                    hashMapOf(
                        "ID token" to authenticationResult.account.idToken,
                        "access token" to authenticationResult.accessToken,
                        "user ID" to authenticationResult.account.id,
                        "expires_on" to authenticationResult.expiresOn.time
                    )
                )
            }

            override fun onError(exception: MsalException) {
                Log.e(TAG, "Authentication failed: ${exception.errorCode}")

                when (exception) {
                    is MsalClientException -> {
                        Log.d(TAG, "Authentication failed: MsalClientException - ${exception.message}")
                        result.error(
                            exception.errorCode ?: "MsalClientException",
                            exception.message,
                            null
                        )
                    }
                    is MsalServiceException -> {
                        Log.d(TAG, "Authentication failed: MsalServiceException - ${exception.message}")
                        result.error(
                            exception.errorCode ?: "MsalServiceException",
                            exception.message,
                            null
                        )
                    }
                    else -> result.error(
                        exception.errorCode ?: "Msal",
                        exception.message,
                        null
                    )
                }
            }

            override fun onCancel() {
                Log.d(TAG, "User cancelled login.")
                result.error("MsalUserCancel", "User cancelled login.", null)
            }
        }
    }

    private fun getAuthSilentCallback(result: Result): AuthenticationCallback {
        return object : AuthenticationCallback {
            override fun onSuccess(authenticationResult: IAuthenticationResult) {
                Log.d(TAG, "Successfully authenticated silently")
                result.success(
                    hashMapOf(
                        "ID token" to authenticationResult.account.idToken,
                        "access token" to authenticationResult.accessToken,
                        "user ID" to authenticationResult.account.id,
                        "expires_on" to authenticationResult.expiresOn.time
                    )
                )
            }

            override fun onError(exception: MsalException) {
                Log.e(TAG, "Silent authentication failed: ${exception.message}")

                when (exception) {
                    is MsalClientException -> {
                        result.error(
                            exception.errorCode ?: "MsalClientException",
                            exception.message,
                            null
                        )
                    }
                    is MsalServiceException -> {
                        result.error(
                            exception.errorCode ?: "MsalServiceException",
                            exception.message,
                            null
                        )
                    }
                    is MsalUiRequiredException -> {
                        result.error(
                            exception.errorCode ?: "MsalUiRequiredException",
                            exception.message,
                            null
                        )
                    }
                    else -> result.error(
                        exception.errorCode ?: "Msal",
                        exception.message,
                        null
                    )
                }
            }

            override fun onCancel() {
                Log.d(TAG, "Silent authentication cancelled.")
                result.error("MsalUserCancel", "Authentication cancelled.", null)
            }
        }
    }
}