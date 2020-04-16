import CJWTKitBoringSSL
import Crypto

internal struct ECDSASigner<CurveType>: JWTAlgorithm where CurveType: EllipticCurve {
    let key: ECDSAKey<CurveType>
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8] where Plaintext: DataProtocol {
        guard let privateKey = self.key.privateKey else {
            fatalError()
        }
        return try Array(privateKey.signature(for: plaintext).rawRepresentation)
    }

    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let signature = try CurveType.signature(rawRepresentation: signature)
        return self.key.publicKey.isValidSignature(signature, for: plaintext)
    }
}

private extension Collection where Element == UInt8 {
    func zeroPrefixed(upTo count: Int) -> [UInt8] {
        if self.count < count {
            return [UInt8](repeating: 0, count: count - self.count) + self
        } else {
            return .init(self)
        }
    }
}
