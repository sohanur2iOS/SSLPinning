//
//  SSLPinningUtility.swift
//  SSLPinning
//
//  Created by Sohanur Rahman on 21/11/24.
//

import Foundation
import CommonCrypto

class SSLPinningUtility {
    
    let localPublicKey = [ "1tY/jIR34efYAQAcKnK8wfOPS7kkRNkL79u+/EpEdKs=" ] // For FastPay Staging Server
    
    let rsa2048Asn1Header:[UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]
    
    func sha256(data : Data) -> String {
        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        
        keyWithHeader.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(keyWithHeader.count), &hash)
        }
        return Data(hash).base64EncodedString()
    }
}
