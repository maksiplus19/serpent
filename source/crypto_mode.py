from typing import Callable, Union, Optional

import numpy as np

from source.serpent import Serpent
from source.support_func import r_solid_index


class CryptoMode:
    @staticmethod
    def electronic_codebook(method: Callable[[bytes, Union[str, bytes]], bytes], prev_chunk: Optional[bytes],
                            chunk: Optional[bytes],
                            prev_encrypted: Optional[bytes], key: str, decryption: bool) -> bytes:
        """Электронная кодовая книга(ECB)"""
        if len(chunk) < 16:
            chunk += b'\x00' * (16 - len(chunk))
        res = method(chunk, key)
        if decryption:
            trash = r_solid_index(res, b'\x00')
            if trash:
                res = res[:trash]
        return res

    @staticmethod
    def block_chain(method: Callable[[bytes, Union[str, bytes]], bytes], prev_chunk: Optional[bytes],
                    chunk: Optional[bytes], prev_encrypted: Optional[bytes],
                    key: str, decryption: bool) -> bytes:
        """Сцепление блоков шифротекста(CBC)"""
        second_chunk = prev_chunk if decryption else prev_encrypted
        # if second_chunk is None:
        #     rnd.seed(key)
        #     second_chunk = bytes(''.join(rnd.choices(symbols, k=alg.batch_size())), encoding='utf8')
        trash = Serpent.batch_size() - len(chunk)
        if trash:
            chunk += b'\x00' * trash
        if decryption:
            chunk = (np.array(bytearray(second_chunk), dtype=np.int8) ^ np.array(bytearray(chunk),
                                                                                 dtype=np.int8)).tobytes()
            res = method(chunk, key)
            trash = r_solid_index(res, b'\x00')
            if trash:
                res = res[:trash]
        else:
            chunk = method(chunk, key)
            res = (np.array(bytearray(second_chunk), dtype=np.uint8) ^ np.array(bytearray(chunk),
                                                                                dtype=np.uint8)).tobytes()
        if decryption:
            trash = r_solid_index(res, b'\x00')
            if trash:
                res = res[:trash]
        return res

    @staticmethod
    def cipher_feedback(method: Callable[[bytes, Union[str, bytes]], bytes], prev_chunk: Optional[bytes],
                        chunk: Optional[bytes], prev_encrypted: Optional[bytes],
                        key: str, decryption: bool) -> bytes:
        """Обратная связь по шифротексту(CFB)"""
        second_chunk = prev_chunk if decryption else prev_encrypted
        # if second_chunk is None:
        #     rnd.seed(key)
        #     second_chunk = bytes(''.join(rnd.choices(symbols, k=alg.batch_size())), encoding='utf8')
        trash = Serpent.batch_size() - len(chunk)
        if trash:
            chunk += b'\x00' * trash
        second_chunk = Serpent.encrypt(second_chunk, key)
        res = (np.array(bytearray(second_chunk), dtype=np.uint8) ^ np.array(bytearray(chunk),
                                                                            dtype=np.uint8)).tobytes()
        if decryption:
            trash = r_solid_index(res, b'\x00')
            if trash:
                res = res[:trash]
        return res

    @staticmethod
    def output_feedback(method: Callable[[bytes, Union[str, bytes]], bytes], prev_chunk: Optional[bytes],
                        chunk: Optional[bytes], prev_encrypted: Optional[bytes],
                        key: str, decryption: bool) -> bytes:
        """Обратная связь по выходу(OFB)"""
        second_chunk = (np.array(bytearray(prev_encrypted), dtype=np.uint8) ^ np.array(bytearray(prev_chunk),
                                                                                       dtype=np.uint8)).tobytes()
        second_chunk = Serpent.encrypt(second_chunk, key)
        trash = Serpent.batch_size() - len(chunk)
        if trash:
            chunk += b'\x00' * trash
        res = (np.array(bytearray(second_chunk), dtype=np.uint8) ^ np.array(bytearray(chunk),
                                                                            dtype=np.uint8)).tobytes()
        if decryption:
            trash = r_solid_index(res, b'\x00')
            if trash:
                res = res[:trash]
        return res


mode_connect = {
    CryptoMode.electronic_codebook.__doc__: CryptoMode.electronic_codebook,
    CryptoMode.block_chain.__doc__: CryptoMode.block_chain,
    CryptoMode.cipher_feedback.__doc__: CryptoMode.cipher_feedback,
    CryptoMode.output_feedback.__doc__: CryptoMode.output_feedback
}
