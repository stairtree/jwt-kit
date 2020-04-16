import CJWTKitBoringSSL
import Crypto

extension JWTSigner {
    public static func es256(key: ECDSAKey<P256>) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            name: "ES256"
        ))
    }

    public static func es384(key: ECDSAKey<P384>) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            name: "ES384"
        ))
    }

    public static func es512(key: ECDSAKey<P521>) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            name: "ES512"
        ))
    }
}
