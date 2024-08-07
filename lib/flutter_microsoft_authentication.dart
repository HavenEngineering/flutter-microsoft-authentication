import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/services.dart';

class FlutterMicrosoftAuthentication {
  static const MethodChannel _channel = const MethodChannel('flutter_microsoft_authentication');

  List<String> _kScopes;
  String _kClientID, _kAuthority;
  String _androidConfigAssetPath;
  String _prompt;
  bool _isAndroid;

  late Future _didAndroidInitialize;

  FlutterMicrosoftAuthentication({
    required String kClientID,
    required String kAuthority,
    required List<String> kScopes,
    required String prompt,
    required String androidConfigAssetPath,
  })   : _kClientID = kClientID,
        _kAuthority = kAuthority,
        _kScopes = kScopes,
        _androidConfigAssetPath = androidConfigAssetPath,
        _prompt = prompt,
        _isAndroid = Platform.isAndroid {
    _initAndroid();
  }

  Map<String, dynamic> _createMethodcallArguments() {
    var res = <String, dynamic>{"kScopes": _kScopes, "kClientID": _kClientID, "kAuthority": _kAuthority, "prompt": _prompt};
    if (Platform.isAndroid) {
      res.addAll({"configPath": _androidConfigAssetPath});
    }
    print(res);
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
}
