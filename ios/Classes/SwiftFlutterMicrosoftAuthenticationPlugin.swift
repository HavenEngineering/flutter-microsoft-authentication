import Flutter
import UIKit
import MSAL

// Using: https://github.com/AzureAD/microsoft-authentication-library-for-objc
// Example code from: https://github.com/Azure-Samples/ms-identity-mobile-apple-swift-objc

public class SwiftFlutterMicrosoftAuthenticationPlugin: NSObject, FlutterPlugin {

  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "flutter_microsoft_authentication", binaryMessenger: registrar.messenger())
    let instance = SwiftFlutterMicrosoftAuthenticationPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {

    let dict = call.arguments! as! NSDictionary
    let clientId = dict["kClientID"] as! String
    let scopes = dict["kScopes"] as! [String]
    let authority = dict["kAuthority"] as! String

    let msalView = ViewController()
    msalView.onInit(clientId: clientId, scopes: scopes, authority: authority, flutterResult: result)

    if(call.method == "acquireTokenInteractively") {
        msalView.acquireTokenInteractively(flutterResult: result)
    } else if(call.method == "acquireTokenSilently") {
        msalView.acquireTokenSilently(flutterResult: result)
    } else if(call.method == "signOut") {
        msalView.signOut(flutterResult: result)
    } else {
        result(FlutterMethodNotImplemented)
    }
  }
}

private class ViewController: UIViewController, UITextFieldDelegate, URLSessionDelegate {

    var kClientID = ""
    var kScopes: [String] = []
    var kAuthority = ""

    var accessToken = "Temporary Placeholder"
    var applicationContext : MSALPublicClientApplication?
    var webViewParamaters : MSALWebviewParameters?

    public func onInit(clientId: String, scopes: [String], authority: String, flutterResult: @escaping FlutterResult) {
        self.kClientID = clientId
        self.kScopes = scopes
        self.kAuthority = authority
        do {
            try self.initMSAL(flutterResult: flutterResult)
        } catch let error {
            print("Unable to create Application Context \(error)")
            flutterResult(FlutterError(code: "CONFIG_ERROR", message: "Unable to create MSALPublicClientApplication", details: nil))
        }
    }
}


// MARK: Initialization

extension ViewController {

    /**

     Initialize a MSALPublicClientApplication with a given clientID and authority

     - clientId:            The clientID of your application, you should get this from the app portal.
     - redirectUri:         A redirect URI of your application, you should get this from the app portal.
     If nil, MSAL will create one by default. i.e./ msauth.<bundleID>://auth
     - authority:           A URL indicating a directory that MSAL can use to obtain tokens. In Azure AD
     it is of the form https://<instance/<tenant>, where <instance> is the
     directory host (e.g. https://login.microsoftonline.com) and <tenant> is a
     identifier within the directory itself (e.g. a domain associated to the
     tenant, such as contoso.onmicrosoft.com, or the GUID representing the
     TenantID property of the directory)
     - error                The error that occurred creating the application object, if any, if you're
     not interested in the specific error pass in nil.
     */
    func initMSAL(flutterResult: @escaping FlutterResult) throws {

        guard let authorityURL = URL(string: kAuthority) else {
            print("Unable to create authority URL")
            flutterResult(FlutterError(code: "INVALID_AUTHORITY", message: "Unable to create authority URL", details: nil))
            return
        }

        let authority = try MSALAADAuthority(url: authorityURL)

        let msalConfiguration = MSALPublicClientApplicationConfig(clientId: kClientID, redirectUri: nil, authority: authority)
        self.applicationContext = try MSALPublicClientApplication(configuration: msalConfiguration)

        let viewController: UIViewController = (UIApplication.shared.delegate?.window??.rootViewController)!;

        self.webViewParamaters = MSALWebviewParameters(authPresentationViewController: viewController)
    }
}


// MARK: Acquiring and using token

extension ViewController {

    func acquireTokenInteractively(flutterResult: @escaping FlutterResult) {

        guard let applicationContext = self.applicationContext else { return }
        guard let webViewParameters = self.webViewParamaters else { return }

        let parameters = MSALInteractiveTokenParameters(scopes: kScopes, webviewParameters: webViewParameters)
        parameters.promptType = .selectAccount;

        applicationContext.acquireToken(with: parameters) { (result: MSALResult?, error: Error?) in

            if let error = error {
                let nsError = error as NSError
                flutterResult(FlutterError(code: nsError.code.description, message: nsError.userInfo.description, details: nsError.domain))
                print("Could not acquire token: \(error)")
                return
            }

            guard let result = result else {
                flutterResult(FlutterError(code: "AUTH_ERROR", message: "Could not acquire token: No result returned", details: nil))
                print("Could not acquire token: No result returned")
                return
            }

            self.accessToken = result.accessToken
            print("Access token is \(self.accessToken)")
            flutterResult(["user ID": result.account.identifier, "access token": result.accessToken, "ID token": result.idToken])
        }

    }

    func acquireTokenSilently(flutterResult: @escaping FlutterResult) {

        guard let applicationContext = self.applicationContext else {
            flutterResult(FlutterError(code: "AUTH_ERROR", message: "Application context not initialized", details: nil))
            return
        }

        let currentAccount = self.currentAccount(flutterResult: flutterResult)

        if currentAccount == nil {
            DispatchQueue.main.async {
                self.acquireTokenInteractively(flutterResult: flutterResult)
            }
            return
        }

        let parameters = MSALSilentTokenParameters(scopes: kScopes, account: currentAccount!)

        applicationContext.acquireTokenSilent(with: parameters) { (result, error) in
            if let error = error as NSError? {
                if error.domain == MSALErrorDomain && error.code == MSALError.interactionRequired.rawValue {
                    DispatchQueue.main.async {
                        self.acquireTokenInteractively(flutterResult: flutterResult)
                    }
                    return
                }

                flutterResult(FlutterError(code: error.code.description, message: error.userInfo.description, details: error.domain))
                print("Could not acquire token silently: \(error)")
                return
            }

            guard let result = result else {
                flutterResult(FlutterError(code: "AUTH_ERROR", message: "Could not acquire token: No result returned", details: nil))
                print("Could not acquire token: No result returned")
                return
            }

            // Token acquired successfully
            self.accessToken = result.accessToken
            print("Refreshed Access token is \(self.accessToken)")

            flutterResult(["user ID": result.account.identifier, "access token": result.accessToken, "ID token": result.idToken])
        }
    }


// MARK: Get account and removing cache

extension ViewController {
    func currentAccount(flutterResult: @escaping FlutterResult) -> MSALAccount? {

        guard let applicationContext = self.applicationContext else { return nil }

        // We retrieve our current account by getting the first account from cache
        // In multi-account applications, account should be retrieved by home account identifier or username instead

        do {

            let cachedAccounts = try applicationContext.allAccounts()

            if !cachedAccounts.isEmpty {
                return cachedAccounts.first
            }

        } catch let error as NSError {
            flutterResult(FlutterError(code: error.code.description, message: error.userInfo.description, details: error.domain))
            print("Didn't find any accounts in cache: \(error)")
        }

        return nil
    }

    /**
     This action will invoke the remove account APIs to clear the token cache
     to sign out a user from this application.
     */
    func signOut(flutterResult: @escaping FlutterResult) {

        guard let applicationContext = self.applicationContext else {
            flutterResult(nil)
            return
        }

        guard let account = self.currentAccount(flutterResult: flutterResult) else {
            flutterResult(nil)
            return
        }

        do {

            /**
             Removes all tokens from the cache for this application for the provided account

             - account:    The account to remove from the cache
             */

            try applicationContext.remove(account)

            self.accessToken = ""
            flutterResult(nil)

        } catch let error as NSError {
            flutterResult(FlutterError(code: error.code.description, message: error.userInfo.description, details: error.domain))
            print("Received error signing account out: \(error)")
        }
    }
}
