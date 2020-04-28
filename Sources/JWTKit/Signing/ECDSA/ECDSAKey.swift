import CJWTKitBoringSSL
import Crypto
import Foundation

public protocol ECDSASignature {}
extension P256.Signing.ECDSASignature: ECDSASignature {}
extension P384.Signing.ECDSASignature: ECDSASignature {}
extension P521.Signing.ECDSASignature: ECDSASignature {}

public protocol ECPrivateKey {
    associatedtype PublicKey
    init<Bytes>(x963Representation: Bytes) throws where Bytes : ContiguousBytes
    var publicKey: PublicKey { get }
}

public protocol ECPublicKey {
    associatedtype S: ECDSASignature
    func isValidSignature<D>(_ signature: S, for data: D) -> Bool where D : DataProtocol
}

public protocol EllipticCurve {
    static func signature<D>(rawRepresentation: D) throws -> ECDSASignature where D : DataProtocol
    associatedtype PublicKey: ECPublicKey
    associatedtype PrivateKey: ECPrivateKey where PrivateKey.PublicKey == PublicKey
}

extension P256: EllipticCurve {
    public typealias PublicKey = Signing.PublicKey
    public typealias PrivateKey = Signing.PrivateKey
    public static func signature<D>(rawRepresentation: D) throws -> ECDSASignature where D : DataProtocol {
        return try Signing.ECDSASignature(rawRepresentation: rawRepresentation)
    }
}
extension P256.Signing.PrivateKey: ECPrivateKey {}
extension P256.Signing.PublicKey: ECPublicKey {}

extension P384: EllipticCurve {
    public typealias PublicKey = Signing.PublicKey
    public typealias PrivateKey = Signing.PrivateKey
    public static func signature<D>(rawRepresentation: D) throws -> ECDSASignature where D : DataProtocol {
        return try Signing.ECDSASignature(rawRepresentation: rawRepresentation)
    }
}
extension P384.Signing.PrivateKey: ECPrivateKey {}
extension P384.Signing.PublicKey: ECPublicKey {}

extension P521: EllipticCurve {
    public typealias PublicKey = Signing.PublicKey
    public typealias PrivateKey = Signing.PrivateKey
    public static func signature<D>(rawRepresentation: D) throws -> ECDSASignature where D : DataProtocol {
        return try Signing.ECDSASignature(rawRepresentation: rawRepresentation)
    }
}
extension P521.Signing.PrivateKey: ECPrivateKey {}
extension P521.Signing.PublicKey: ECPublicKey {}

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


public final class ECDSAKey<CurveType>: OpenSSLKey where CurveType: EllipticCurve {
    
    public static func generate(curve: Curve = .p521) throws -> ECDSAKey {
        // This errors because there's no generic constraint to require CurveType == P256
        // To do this generically, need to be able to validate `CurveType` corresponds to `curve`,
        //  there's no protocol requirement that can do this right now.
        // There's also no protocol requirement of a private key initializer, so can't do `CurveType.PrivateKey()`
        switch curve {
        case .p256:
            let privateKey = P256.Signing.PrivateKey()
            return .init(privateKey: privateKey)
        case .p384:
            let privateKey = P384.Signing.PrivateKey()
            return .init(privateKey: privateKey)
        case .p521:
            let privateKey = P521.Signing.PrivateKey()
            return .init(privateKey: privateKey)
        }
        
    }
    
    public static func `public`<Data, CurveType>(pem data: Data) throws -> ECDSAKey<CurveType> where Data: DataProtocol, CurveType: EllipticCurve {
        let pemString = String(decoding: data, as: UTF8.self)
        let strippedPem = pemString.replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----\n", with: "").replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "").replacingOccurrences(of: "\n", with: "")
        
        guard let data = Foundation.Data(base64Encoded: strippedPem) else {
            throw JWTError.signatureVerifictionFailed
        }
        
        let key = try ECDSAKey.convertFromPem(data.copyBytes())
        return .init(publicKey: key)
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
        
//        let curve = ECDSAKey.getCurve(from: c)
        let keyData = ECDSAKey.convertECKeyToX963Representation(from: c, for: Curve.p256)
        return try self.init(privateKey: .init(x963Representation: keyData))
    }
    
    let publicKey: CurveType.PublicKey
    let privateKey: CurveType.PrivateKey?
    
    init(publicKey: CurveType.PublicKey) {
        self.publicKey = publicKey
        self.privateKey = nil
    }
    
    init(privateKey: CurveType.PrivateKey) {
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
        case NID_X9_62_prime256v1:
            return .p256
        case NID_secp384r1:
            return .p384
        case NID_secp521r1:
            return .p521
        default:
            fatalError("Unsupported ECDSA key curve: \(curveName)")
        }
    }
    
    // See https://github.com/apple/swift-crypto/blob/64a1a98e47e6643e6d43d30b87a244483b51d8ad/Tests/CryptoTests/ECDH/BoringSSL/secpECDH_Runner_boring.swift#L64-L83
    private static func convertFromPem(_ derBytes: [UInt8]) throws -> P256.Signing.PublicKey {
        // Bad news everybody. Using the EC DER parsing from OpenSSL limits our ability to tell the difference
        // between an invalid SPKI layout (which we don't care about, as the production library doesn't support DER-encoded
        // EC keys) and a SPKI layout that is syntactically valid but doesn't represent a valid point on the curve. We _do_
        // care about passing this into the production library.
        //
        // This means we've only one option: we have to implement "just enough" ASN.1.
        var derBytes = derBytes[...]
        let spki = try ASN1SubjectPublicKeyInfo(fromASN1: &derBytes)
        guard derBytes.count == 0, spki.algorithm.algorithm == ASN1ObjectIdentifier.AlgorithmIdentifier.idEcPublicKey else {
            throw JWTError.signatureVerifictionFailed
        }

        // Ok, the bitstring we are holding is the X963 representation of the public key. Try to create it.
        let key = try P256.Signing.PublicKey(x963Representation: spki.subjectPublicKey)
        return key
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

extension Curve: OpenSSLSupportedNISTCurve {
    @usableFromInline
    var group: BoringSSLEllipticCurveGroup {
        return try! .init(self)
    }
    
    
}
