//
//  ViewController.swift
//  SSLPinning
//
//  Created by Sohanur Rahman on 20/11/24.
//

import UIKit
import Alamofire

class ViewController: UIViewController {

    lazy var button = UIButton()
    
    var afManager = AlamofireSSLPinning()
    
    var afTrustKitManager = AlamofireSSLPinningWithTrustKit()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .white
                
        button = UIButton(frame: CGRect(x: 50, y: 100, width: view.bounds.width - 100, height: 100))
        button.backgroundColor = .black
        button.setTitle("Check SSL Pinning", for: .normal)
        button.addTarget(self, action: #selector(buttonAction), for: .touchUpInside)
        
        view.addSubview(button)
    }
    
    @objc func buttonAction() {
        
        URLSessionSSLPinning().checkSSLPinning()
        
        afManager.checkSSLPinning()
        
        afTrustKitManager.checkSSLPinning()
    }
}

import Foundation
import CommonCrypto

enum CryptoError: Error {
    case encryptionFailure
    case decryptionFailure
    case keyGenerationFailure
}


struct AES256CBCAlgorithm {
    
    private static let keyLength = kCCKeySizeAES256
    private static let blockSize = kCCBlockSizeAES128
    private static let options = CCOptions(kCCOptionPKCS7Padding)

    static func generateRandomIV() -> Data? {
        var iv = [UInt8](repeating: 0, count: blockSize)
        let status = SecRandomCopyBytes(kSecRandomDefault, iv.count, &iv)
        guard status == errSecSuccess else { return nil }
        return Data(iv)
    }
    
    static func randomIvString(length: Int) -> String {
      let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!@#%^&*()_+"
      return String((0..<length).map{ _ in characters.randomElement()! })
    }

    static func encrypt(data: Data, key: Data, iv: Data) throws -> Data {
        var encryptedData = Data(count: data.count + blockSize)
        var encryptedDataLength = 0

        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                data.withUnsafeBytes { dataBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        options,
                        keyBytes.baseAddress, keyLength,
                        ivBytes.baseAddress,
                        dataBytes.baseAddress, data.count,
                        encryptedData.withUnsafeMutableBytes { $0.baseAddress }, encryptedData.count,
                        &encryptedDataLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw CryptoError.encryptionFailure
        }

        encryptedData.count = encryptedDataLength
        return encryptedData
    }

    static func decrypt(data: Data, key: Data, iv: Data) throws -> Data {
        var decryptedData = Data(count: data.count + blockSize)
        var decryptedDataLength = 0

        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                data.withUnsafeBytes { dataBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        options,
                        keyBytes.baseAddress, keyLength,
                        ivBytes.baseAddress,
                        dataBytes.baseAddress, data.count,
                        decryptedData.withUnsafeMutableBytes { $0.baseAddress }, decryptedData.count,
                        &decryptedDataLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw CryptoError.decryptionFailure
        }

        decryptedData.count = decryptedDataLength
        return decryptedData
    }
}


