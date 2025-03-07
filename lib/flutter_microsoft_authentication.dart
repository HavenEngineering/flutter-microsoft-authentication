import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/services.dart';

class FlutterMicrosoftAuthentication {
  static const MethodChannel _channel = const MethodChannel('flutter_microsoft_authentication');

  List<String> _kScopes;
  String _kClientID, _kAuthority;
  String _androidConfigAssetPath;
  bool _isAndroid;
  bool? shouldLoginAutomatically;

  late Future _didAndroidInitialize;

  FlutterMicrosoftAuthentication({
    required String kClientID,
    required String kAuthority,
    required List<String> kScopes,
    required String androidConfigAssetPath,
    bool? shouldLoginAutomatically,
  })  : _kClientID = kClientID,
        _kAuthority = kAuthority,
        _kScopes = kScopes,
        shouldLoginAutomatically = shouldLoginAutomatically,
        _androidConfigAssetPath = androidConfigAssetPath,
        _isAndroid = Platform.isAndroid {
    _initAndroid();
  }

  Map<String, dynamic> _createMethodcallArguments() {
    var res = <String, dynamic>{
      "kScopes": _kScopes,
      "kClientID": _kClientID,
      "kAuthority": _kAuthority,
      "shouldLoginAutomatically": shouldLoginAutomatically,
    };
    if (Platform.isAndroid) {
      res.addAll({"configPath": _androidConfigAssetPath});
    }
    return res;
  }

  Future<void> _initAndroid() async {
    if (_isAndroid) _didAndroidInitialize = _channel.invokeMethod("init", _createMethodcallArguments());
  }

  /// Acquire auth tokens with interactive flow.
  Future<Map> get acquireTokenInteractively async {
    if (_isAndroid) await _didAndroidInitialize;
    final dynamic result = await _channel.invokeMethod('acquireTokenInteractively', _createMethodcallArguments());
    return result;
  }

  /// Acquire auth token silently.
  Future<Map> get acquireTokenSilently async {
    if (_isAndroid) await _didAndroidInitialize;
    final dynamic result = await _channel.invokeMethod('acquireTokenSilently', _createMethodcallArguments());
    return result;
  }

  /// Refreshes the access token using the refresh token.
  /// This method should be called when the access token is about to expire.
  /// Returns a Map containing the refreshed tokens and their expiration time.
  /// Throws a PlatformException if the refresh fails.
  Future<Map> refreshToken() async {
    if (_isAndroid) await _didAndroidInitialize;
    try {
      final dynamic result = await _channel.invokeMethod('refreshToken', _createMethodcallArguments());
      return result;
    } on PlatformException catch (error) {
      if (error.code == "InteractiveAuthRequired") {
        // Special handling for when silent refresh isn't possible and interactive auth is needed
        // Rethrow with the same code so callers can handle this case specifically
        rethrow;
      } else {
        rethrow;
      }
    }
  }

  /// Sign out of current active account.
  Future<void> get signOut async {
    if (_isAndroid) await _didAndroidInitialize;
    try {
      return await _channel.invokeMethod('signOut', _createMethodcallArguments());
    } on PlatformException catch (error) {
      if (error.code == "no_current_account") {
        return;
      } else {
        rethrow;
      }
    }
  }

  /// Checks if there's a current active account.
  /// Returns true if there's an active account, false otherwise.
  Future<bool> get hasCurrentAccount async {
    if (_isAndroid) await _didAndroidInitialize;
    try {
      // Using acquireTokenSilently as a way to check for current account
      // If it succeeds, there's an active account
      await _channel.invokeMethod('acquireTokenSilently', _createMethodcallArguments());
      return true;
    } on PlatformException catch (error) {
      if (error.code == "MsalClientException" &&
          error.message?.contains("No active account") == true) {
        return false;
      }
      // For other errors, we still consider there's no valid current account
      return false;
    }
  }
}