//
//  AlamofireSSLPinning.swift
//  SSLPinning
//
//  Created by Sohanur Rahman on 21/11/24.
//

import Alamofire
import Foundation
import CommonCrypto

class AlamofireSSLPinning {
    
    var afSession: Session!
    
    init() {
        afSession = Session(
            configuration: URLSessionConfiguration.default, 
            delegate: AlamofireSessionDelegate.init()
        )
    }
    
    func checkSSLPinning() {
        
        // Make sure afSession is not nil and is retained
        guard let afSession = self.afSession else {
            print("Alamofire session is not initialized.")
            return
        }
        
        afSession.request("https://staging-apigw-personal.fast-pay.iq/api/v1/version")
            .validate()
            .response{ response in
                switch response.result {
                    
                case .success(let value):
                    print("\n\nSSL Pinning Successfull for Alamofire and Response Model Decoded to JSON: \(String(describing: value))")
                    
                case .failure(let error):
                    
                    switch error {
                        
                    case .serverTrustEvaluationFailed(let reason):
                        print("Trusted Issue Occured!!! \n\(reason)")
                        
                    default:
                        if String(describing: error.localizedDescription) == "URLSessionTask failed with error: cancelled" {
                            print("\n\n\n SSL Pinning Failed For Alamofire!!! \n\n\n")
                        }
                        else{
                            print("Error Happened! Reason: \(error.localizedDescription)") 
                        }
                    }
                }
            }
    }
}

class AlamofireSessionDelegate: SessionDelegate {
    
    override func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust, let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            return
        }
        
        if let serverPublicKey = SecCertificateCopyKey(certificate), let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey, nil) {
            let data: Data = serverPublicKeyData as Data
            let serverHashKey = SSLPinningUtility().sha256(data: data)
            
            print("Current Server Key: \(serverHashKey)")
            
            if SSLPinningUtility().localPublicKey.contains( serverHashKey ) { // If there is multiple Base URL then we need to check contains.
                let credential: URLCredential = URLCredential(trust: serverTrust)
                print("\nPublic Key pinning is successfull")
                completionHandler(.useCredential, credential)
            } else {
                print("\nPublic Key pinning is failed")
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        }
    }
}
