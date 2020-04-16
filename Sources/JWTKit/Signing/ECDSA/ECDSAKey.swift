import CJWTKitBoringSSL
import Crypto
import Foundation

public final class ECDSAKey: OpenSSLKey {
    
    public enum Curve {
        case p256
        case p384
        case p521
        
        @usableFromInline
        var cName: Int32 {
            switch self {
            case .p256:
                return NID_X9_62_prime256v1
            case .p384:
                return NID_secp384r1
            case .p521:
                return NID_secp521r1
            }
        }
    }
    
    public static func generate(curve: Curve = .p521) throws -> ECDSAKey {
        let privateKey = P256.Signing.PrivateKey()
        return .init(privateKey: privateKey)
    }
    
    public static func `public`<Data>(pem data: Data) throws -> ECDSAKey
        where Data: DataProtocol
    {
        //        let c = try self.load(pem: data) { bio in
        //            CJWTKitBoringSSL_PEM_read_bio_EC_PUBKEY(bio, nil, nil, nil)
        //        }
        //        // c is a OpaquePointer to `EC_KEY`
        //        let publicKey = UnsafePointer<UInt8>(c)
        //        let publicKeyData = Foundation.Data(bytes: publicKey, count: 33)
        //        CJWTKitBoringSSL_EC_KEY_free(c)
        //        return try self.init(privateKey: .init(rawRepresentation: privateKeyData))
//        fatalError()
        throw JWTError.signatureVerifictionFailed
    }
    
    public static func `private`<Data>(pem data: Data) throws -> ECDSAKey
        where Data: DataProtocol
    {
        let c = try self.load(pem: data) { bio in
            return CJWTKitBoringSSL_PEM_read_bio_ECPrivateKey(bio, nil, nil, nil)
        }
        defer {
            CJWTKitBoringSSL_EC_KEY_free(c)
        }
        
        let curve = ECDSAKey.getCurve(from: c)
        let keyData = ECDSAKey.convertECKeyToX963Representation(from: c, for: curve)
        return try self.init(privateKey: .init(x963Representation: keyData))
    }
    
    let publicKey: P256.Signing.PublicKey
    let privateKey: P256.Signing.PrivateKey?
    
    init(publicKey: P256.Signing.PublicKey) {
        self.publicKey = publicKey
        self.privateKey = nil
    }
    
    init(privateKey: P256.Signing.PrivateKey) {
        self.privateKey = privateKey
        self.publicKey = privateKey.publicKey
    }
    
    // See https://github.com/apple/swift-crypto/blob/cce48362a4bfa167cd9ac2acca522f23f2fe1561/Sources/Crypto/Keys/EC/BoringSSL/NISTCurvesKeys_boring.swift
    static func convertECKeyToX963Representation(from key: OpaquePointer, for curve: OpenSSLSupportedNISTCurve) -> Data {
        // Get group and pointByteCount
        let group = curve.group
        let pointByteCount = group.coordinateByteCount
        let privateKey = try! ArbitraryPrecisionInteger(copying: CJWTKitBoringSSL_EC_KEY_get0_private_key(key)!)
        let publicKeyPoint = try! EllipticCurvePoint(copying: CJWTKitBoringSSL_EC_KEY_get0_public_key(key)!, on: group)
        let (x, y) = try! publicKeyPoint.affineCoordinates(group: group)
        var bytes = Data()
        bytes.reserveCapacity(1 + (group.coordinateByteCount * 3))
        
        // These try!s should only trigger in the case of internal consistency errors.
        bytes.append(0x4)
        try! bytes.append(bytesOf: x, paddedToSize: pointByteCount)
        try! bytes.append(bytesOf: y, paddedToSize: pointByteCount)
        try! bytes.append(bytesOf: privateKey, paddedToSize: pointByteCount)
        
        return bytes
    }

    static func getCurve(from key: OpaquePointer) -> Curve {
        let curveName = CJWTKitBoringSSL_EC_GROUP_get_curve_name(CJWTKitBoringSSL_EC_KEY_get0_group(key))
        switch curveName {
        case NID_secp256k1:
            return .p256
        case NID_secp384r1:
            return .p384
        case NID_secp521r1:
            return .p521
        default:
            fatalError("Unsupported ECDSA key curve: \(curveName)")
        }
    }
    
}

@usableFromInline
protocol OpenSSLSupportedNISTCurve {
    @inlinable
    var group: BoringSSLEllipticCurveGroup { get }
}

extension OpenSSLSupportedNISTCurve {
    @inlinable
    var coordinateByteCount: Int {
        return self.group.coordinateByteCount
    }
}

extension ECDSAKey.Curve: OpenSSLSupportedNISTCurve {
    @usableFromInline
    var group: BoringSSLEllipticCurveGroup {
        return try! .init(self)
    }
    
    
}
