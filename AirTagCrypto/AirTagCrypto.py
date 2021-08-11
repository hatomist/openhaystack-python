import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class AirTagCrypto:
    def __init__(self, private_key: str = None):
        if private_key is not None:
            self._private_key = base64.b64decode(private_key)
        else:
            self._private_key = self.__generate_new_private_key()

    def get_advertisement_key(self) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self
                      .__derive_elliptic_curve_private_key(self._private_key, ec.SECP224R1())
                      .public_key()
                      .public_bytes(Encoding.X962, PublicFormat.CompressedPoint)[1:])
        return base64.b64encode(digest.finalize()).decode()

    @staticmethod
    def __derive_elliptic_curve_private_key(private_key: bytes, curve: ec.EllipticCurve):
        return ec.derive_private_key(int.from_bytes(private_key, 'big'), curve, default_backend())

    def __derive_shared_key_from_private_key_and_eph_key(self, eph_key: bytes):
        curve = ec.SECP224R1()
        private_key = self.__derive_elliptic_curve_private_key(self._private_key, curve)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, eph_key)
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        return shared_key

    @staticmethod
    def __kdf(shared_key, eph_key: bytes, counter=1):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_key)

        counter_data = bytes(counter.to_bytes(4, 'big'))
        digest.update(counter_data)
        digest.update(eph_key)
        return digest.finalize()

    @staticmethod
    def __decrypt_payload(enc_data: bytes, symmetric_key: bytes, tag: bytes):
        decryption_key = symmetric_key[:16]
        iv = symmetric_key[16:]
        cipher = Cipher(algorithms.AES(decryption_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(enc_data) + decryptor.finalize()

    @staticmethod
    def __decode_tag(data: bytes):
        latitude = int.from_bytes(data[0:4], 'big', signed=True) / 10000000.0
        longitude = int.from_bytes(data[4:8], 'big', signed=True) / 10000000.0
        confidence = int.from_bytes(data[8:9], 'big')
        return {'lat': latitude, 'lon': longitude, 'conf': confidence}

    @staticmethod
    def __generate_new_private_key():
        curve = ec.SECP224R1()
        return ec.generate_private_key(curve).private_numbers().private_value.to_bytes(28, 'big')

    def decrypt_message(self, payload):
        data = base64.b64decode(payload)
        timestamp = int.from_bytes(data[0:4], 'big')
        eph_key = data[5:62]
        shared_key = self.__derive_shared_key_from_private_key_and_eph_key(eph_key)
        derived_key = self.__kdf(shared_key, eph_key)
        enc_data = data[62:72]
        tag = data[72:]
        decrypted = self.__decrypt_payload(enc_data, derived_key, tag)

        ret = self.__decode_tag(decrypted)
        ret['timestamp'] = timestamp + 978307200  # 978307200 is delta between unix and cocoa timestamps
        return ret
