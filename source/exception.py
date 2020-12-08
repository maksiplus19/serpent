class LenError(Exception):
    def __init__(self, expected_len: int, real_len: int):
        super(LenError, self).__init__()
        self._exp_len = expected_len
        self._r_len = real_len

    def __str__(self):
        return f'Expected len of block {self._exp_len} got instead {self._r_len}'
