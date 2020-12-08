import os
from functools import partial
from typing import Union, List, Callable, Optional

from source.signals import UpdateSignal

ENCRYPTED_FILE_EXTENSION = 'crpt'


def rounded_bit_move_left(n: int, step: int, size: int) -> int:
    n <<= step
    if n.bit_length() <= size:
        return n
    tail = n >> size
    n |= tail
    n &= (1 << size) - 1
    return n


def rounded_bit_move_right(n: int, step: int, size: int) -> int:
    begin = n & ((1 << step) - 1)
    n >>= step
    n |= begin << (size - step)
    return n


l_move32 = partial(rounded_bit_move_left, size=32)
r_move32 = partial(rounded_bit_move_right, size=32)


def permutation(num: int, perm: Union[List]) -> int:
    result = 0
    for k in perm:
        result <<= 1
        result |= (num >> k) & 1
    return result


def r_solid_index(s: Union[str, bytes], char: Union[str, bytes]) -> int:
    i = len(s) - 1
    while i and s[i] == char:
        i -= 1
    return i + 1


Mode = Callable[
    [Callable[[bytes, Union[str, bytes]], bytes], bytes, Optional[bytes], Optional[bytes], str, bool], bytes]


def encrypt_decrypt(input_file: str, mode: Mode, method: Callable[[bytes, Union[str, bytes]], bytes],
                    signal: UpdateSignal, key: str, decryption: bool = False, ext: str = None,
                    vector: str = None) -> Optional[str]:
    if decryption and ext is None:
        raise ValueError('Decryption need original file extension')

    output_file = input_file.rsplit('.', maxsplit=1)
    output_file[-1] = f'{ext}' if decryption else ENCRYPTED_FILE_EXTENSION
    output_file = '_decrypted.'.join(output_file) if decryption else '.'.join(output_file)
    if not os.path.exists(input_file):
        return None

    file_size = os.path.getsize(input_file)
    progress = 0
    batch_size = 16
    signal.update.emit(0)
    vector = bytes(vector, 'utf8')
    with open(input_file, mode='rb') as in_file:
        with open(output_file, mode='wb') as out_file:
            prev_chunk = vector
            prev_encrypted = vector
            for chunk in iter(partial(in_file.read, batch_size), b''):
                encrypted = mode(method, prev_chunk, chunk, prev_encrypted, key, decryption)
                prev_chunk = chunk
                prev_encrypted = encrypted
                out_file.write(encrypted)
                progress += batch_size
                signal.update.emit(int(progress / file_size * 100))
    return output_file
