//
//  AlamofireSSLPinningWithTrustKit.swift
//  SSLPinning
//
//  Created by Sohanur Rahman on 20/11/24.
//

import Alamofire
import TrustKit
import Foundation
import CommonCrypto

class AlamofireSSLPinningWithTrustKit {
    
    var afSession: Session!
    
    init() {
        
        let trustKitConfig = [
                    kTSKSwizzleNetworkDelegates: false,
                    kTSKPinnedDomains: [
                        "staging-apigw-personal.fast-pay.iq": [
                            kTSKEnforcePinning: true,
                            kTSKIncludeSubdomains: true,
                            kTSKPublicKeyHashes: [
                                "1tY/jIR34efYAQAcKnK8wfOPS7kkRNkL79u+/EpEdKs=",
                                "1tY/jIR34efYAQAcKnK8wfOPS7ekRNkL79u+/EpEdKs="
                            ],
                        ],
                        
                        "staging-apigw-perenal.fast-pay.iq": [
                            kTSKEnforcePinning: true,
                            kTSKIncludeSubdomains: true,
                            kTSKPublicKeyHashes: [
                                "1tY/jIR34efYAQAcKnK8wfOPS7kkRNkL79u+/EpEdKs=",
                                "1tY/jIR34efYAQAcKnK8wfOPS7ekRNkL79u+/EpEdKs="
                            ],
                        ],
                        
                        // Add More if required
                    ]
        ] as [String : Any]
                
        TrustKit.initSharedInstance(withConfiguration: trustKitConfig)
        
        
        let certificateName = "staging.fast-pay.iq"
        
        guard let certificatePath = Bundle.main.path(forResource: certificateName, ofType: "cer"),
              let certificateData = NSData(contentsOfFile: certificatePath),
              let certificate = SecCertificateCreateWithData(nil, certificateData) else {
            print("Certificate not found or invalid")
            return
        }
        
        let evaluators: [String: ServerTrustEvaluating] = [
            "staging-apigw-personal.fast-pay.iq": PinnedCertificatesTrustEvaluator(
                certificates: [certificate],
                acceptSelfSignedCertificates: false, // Adjust based on your requirements
                performDefaultValidation: true,     // Validate certificate chain
                validateHost: true                  // Validate host
            )
        ]
        
        let serverTrustManager = ServerTrustManager(evaluators: evaluators)
        
        // Retain the Session object
        afSession = Session(
            configuration: URLSessionConfiguration.default, 
            delegate: AlamofireWithTrustKitSessionDelegate.init()
//            serverTrustManager: serverTrustManager
        )
    }
    
    func checkSSLPinning() {
        
        
        print("\n\n\n\nChecking Alamofire SSL Pinning\n\n\n\n")
        
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
                    print("\n\nSSL Pinning Successfull for Alamofire With TrustKit and Response Model Decoded to JSON: \(String(describing: value))")
                    
                case .failure(let error):
                    
                    switch error {
                        
                    case .serverTrustEvaluationFailed(let reason):
                        print("Trusted Issue Occured!!! \n\(reason)")
                        
                    default:
                        if String(describing: error.localizedDescription) == "URLSessionTask failed with error: cancelled" {
                            print("\n\n\n SSL Pinning Failed For Alamofire With TrustKit!!! \n\n\n")
                        }
                        else{
                            print("Error Happened! Reason: \(error.localizedDescription)") 
                        }
                    }
                }
            }
    }
}

class AlamofireWithTrustKitSessionDelegate: SessionDelegate {
    
    override func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        if TrustKit.sharedInstance().pinningValidator.handle(challenge, completionHandler: completionHandler) == false {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
