import 'dart:async';
import 'dart:io' show Platform;
import 'package:flutter/services.dart';

class FlutterMicrosoftAuthentication {
  static const MethodChannel _channel = const MethodChannel('flutter_microsoft_authentication');

  List<String> _kScopes;
  String _kClientID, _kAuthority;
  String _androidConfigAssetPath;
  Future _didAndroidInitialize;

  FlutterMicrosoftAuthentication({
    String kClientID,
    String kAuthority,
    List<String> kScopes,
    String androidConfigAssetPath,
  }) {
    _kClientID = kClientID;
    _kAuthority = kAuthority;
    _kScopes = kScopes;
    _androidConfigAssetPath = androidConfigAssetPath;
    _initAndroid();
  }

  Map<String, dynamic> _createMethodcallArguments() {
    var res = <String, dynamic>{"kScopes": _kScopes, "kClientID": _kClientID, "kAuthority": _kAuthority};
    if (Platform.isAndroid && _androidConfigAssetPath != null) {
      res.addAll({"configPath": _androidConfigAssetPath});
    }
    print(res);
    return res;
  }

  Future<void> _initAndroid() async {
    if (Platform.isAndroid) _didAndroidInitialize = _channel.invokeMethod("init", _createMethodcallArguments());
  }

  /// Acquire auth tokens with interactive flow.
  Future<Map> get acquireTokenInteractively async {
    await _didAndroidInitialize;
    final dynamic result = await _channel.invokeMethod('acquireTokenInteractively', _createMethodcallArguments());
    return result;
  }

  /// Acquire auth token silently.
  Future<Map> get acquireTokenSilently async {
    await _didAndroidInitialize;
    final dynamic result = await _channel.invokeMethod('acquireTokenSilently', _createMethodcallArguments());
    return result;
  }

  /// Sign out of current active account.
  Future<void> get signOut async {
    await _didAndroidInitialize;
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
}
