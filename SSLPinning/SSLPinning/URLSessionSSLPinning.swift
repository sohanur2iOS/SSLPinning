//
//  URLSessionSSLPinning.swift
//  SSLPinning
//
//  Created by Sohanur Rahman on 20/11/24.
//

import Foundation
import UIKit
import CommonCrypto

class URLSessionSSLPinning : NSObject {
    
    func checkSSLPinning() {
        
        print("\n\n\n\nChecking URLSession SSL Pinning\n\n\n\n")
        
        var request = URLRequest(url: URL(string: "https://staging-apigw-personal.fast-pay.iq/api/v1/version")!)
        request.httpMethod = "GET"
        
        let session = URLSession.init(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        
        let task = session.dataTask(with: request) { data, response, error in
            
            
            if let error, error.localizedDescription == "cancelled" {
                print("\n\n\n\nSSL Pinning Failed For URLSession!\n\n\n\n")
                return
            }
            else if let data {
                do {
                    let jsonObject = try JSONSerialization.jsonObject(with: data, options: [])
                    print("\nSSL Pinning Successfull for URLSession and Response Model Decoded to JSON")
                } catch {
                    print("\nNetwork Call Failed", error)
                }
            }
        }
        task.resume()
    }
}

extension URLSessionSSLPinning: URLSessionDelegate {
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust, let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            return
        }
        
        if let serverPublicKey = SecCertificateCopyKey(certificate), let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey, nil) {
            let data: Data = serverPublicKeyData as Data
            let serverHashKey = SSLPinningUtility().sha256(data: data)
            
            print("Current Server Key: \(serverHashKey)")
            
            if  SSLPinningUtility().localPublicKey.contains( serverHashKey ) { // If there is multiple Base URL then we need to check contains.
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



