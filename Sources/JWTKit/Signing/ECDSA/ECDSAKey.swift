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
        //        guard let c = CJWTKitBoringSSL_EC_KEY_new_by_curve_name(curve.cName) else {
        //            throw JWTError.signingAlgorithmFailure(ECDSAError.newKeyByCurveFailure)
        //        }
        //        guard CJWTKitBoringSSL_EC_KEY_generate_key(c) != 0 else {
        //            throw JWTError.signingAlgorithmFailure(ECDSAError.generateKeyFailure)
        //        }
        //        return .init(c)
        fatalError()
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
        fatalError()
    }
    
    public static func `private`<Data>(pem data: Data) throws -> ECDSAKey
        where Data: DataProtocol
    {
        let c = try self.load(pem: data) { bio in
            return CJWTKitBoringSSL_PEM_read_bio_ECPrivateKey(bio, nil, nil, nil)
        }
        // c is a OpaquePointer to `EC_KEY`, need to convert it to `EC_POINT`
        CJWTKitBoringSSL_EC_KEY_get0_public_key(c)
        
        
        let privateKey = UnsafePointer<UInt8>(c)
        let privateKeyData = Foundation.Data(bytes: privateKey, count: 32)
        CJWTKitBoringSSL_EC_KEY_free(c)
        return try self.init(privateKey: .init(rawRepresentation: privateKeyData))
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
    func convertECKeyToX963Representation(from key: OpaquePointer, for curve: OpenSSLSupportedNISTCurve.Type) -> Data {
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
    
}

@usableFromInline
protocol OpenSSLSupportedNISTCurve {
    @inlinable
    static var group: BoringSSLEllipticCurveGroup { get }
}

extension OpenSSLSupportedNISTCurve {
    @inlinable
    static var coordinateByteCount: Int {
        return self.group.coordinateByteCount
    }
}
