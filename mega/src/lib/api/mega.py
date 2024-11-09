import binascii
import math
import random
import logging
import hashlib
from telnetlib import RSP
from src.exeptions import RequestError
from .request import api_request
from typing import Optional
import re
from .crypto import (a32_to_base64, encrypt_key, base64_url_encode,
                     encrypt_attr, base64_to_a32, base64_url_decode,
                     decrypt_attr, a32_to_str, get_chunks, str_to_a32,
                     decrypt_key, mpi_to_int, stringhash, prepare_key, make_id,
                     makebyte, modular_inverse)

logger: logging.Logger = logging.getLogger(__name__)


class Mega:
    def __init__(self, options: Optional[dict] = None):
        self.schema: str = 'https'
        self.domain: str = 'mega.co.nz'
        self.timeout: int = 160  # max secs to wait for resp from api requests
        self.sid: Optional[int] = None
        self.sequence_num: int = random.randint(0, 0xFFFFFFFF)
        self.request_id: str = make_id(10)
        self._trash_folder_node_id: Optional[int] = None

        if options is None:
            options = {}
        self.options = options

    def login(self, email: str, password: str):
        self._login_user(email, password)
        self._trash_folder_node_id = self.get_node_by_type(4)[0]
        logger.info('Login complete')
        return self

    def _login_user(self, email: str, password: str):
        logger.info('Logging in user...')
        email = email.lower()
        get_user_salt_resp = self._api_request({'a': 'us0', 'user': email})
        user_salt = None
        try:
            user_salt = base64_to_a32(get_user_salt_resp['s'])
        except KeyError:
            # v1 user account
            password_aes = prepare_key(str_to_a32(password))
            user_hash = stringhash(email, password_aes)
        else:
            # v2 user account
            pbkdf2_key = hashlib.pbkdf2_hmac(hash_name='sha512',
                                             password=password.encode(),
                                             salt=a32_to_str(user_salt),
                                             iterations=100000,
                                             dklen=32)
            password_aes = str_to_a32(pbkdf2_key[:16])
            user_hash = base64_url_encode(pbkdf2_key[-16:])
        resp = self._api_request({'a': 'us', 'user': email, 'uh': user_hash})
        if isinstance(resp, int):
            raise RequestError(resp)
        self._login_process(resp, password_aes)
        
    def _login_process(self, resp, password: str):
        encrypted_master_key = base64_to_a32(resp['k'])
        self.master_key = decrypt_key(encrypted_master_key, password)
        if 'tsid' in resp:
            tsid = base64_url_decode(resp['tsid'])
            key_encrypted = a32_to_str(
                encrypt_key(str_to_a32(tsid[:16]), self.master_key))
            if key_encrypted == tsid[-16:]:
                self.sid = resp['tsid']
        elif 'csid' in resp:
            encrypted_rsa_private_key = base64_to_a32(resp['privk'])
            rsa_private_key = decrypt_key(encrypted_rsa_private_key,
                                          self.master_key)

            private_key = a32_to_str(rsa_private_key)
            # The private_key contains 4 MPI integers concatenated together.
            rsa_private_key = [0, 0, 0, 0]
            for i in range(4):
                # An MPI integer has a 2-byte header which describes the number
                # of bits in the integer.
                bitlength = (private_key[0] * 256) + private_key[1]
                bytelength = math.ceil(bitlength / 8)
                # Add 2 bytes to accommodate the MPI header
                bytelength += 2
                rsa_private_key[i] = mpi_to_int(private_key[:bytelength])
                private_key = private_key[bytelength:]

            first_factor_p = rsa_private_key[0]
            second_factor_q = rsa_private_key[1]
            private_exponent_d = rsa_private_key[2]
            # In MEGA's webclient javascript, they assign [3] to a variable
            # called u, but I do not see how it corresponds to pycryptodome's
            # RSA.construct and it does not seem to be necessary.
            rsa_modulus_n = first_factor_p * second_factor_q
            phi = (first_factor_p - 1) * (second_factor_q - 1)
            public_exponent_e = modular_inverse(private_exponent_d, phi)

            rsa_components = (
                rsa_modulus_n,
                public_exponent_e,
                private_exponent_d,
                first_factor_p,
                second_factor_q,
            )
            rsa_decrypter = RSP.construct(rsa_components)

            encrypted_sid = mpi_to_int(base64_url_decode(resp['csid']))

            sid = '%x' % rsa_decrypter._decrypt(encrypted_sid)
            sid = binascii.unhexlify('0' + sid if len(sid) % 2 else sid)
            self.sid = base64_url_encode(sid[:43])

        
    def _api_request(self, data: dict):
        # api_request(data)
        params = {'id': self.sequence_num}
        self.sequence_num += 1

        if self.sid:
            params.update({'sid': self.sid})

        # ensure input data is a list
        if not isinstance(data, list):
            data = [data]

        url = f'{self.schema}://g.api.{self.domain}/cs'
        return api_request(params, data, self.schema, self.domain, self.timeout)


    def _parse_url(self, url):
        """Parse file id and key from url."""
        if '/file/' in url:
            # V2 URL structure
            url = url.replace(' ', '')
            file_id = re.findall(r'\W\w\w\w\w\w\w\w\w\W', url)[0][1:-1]
            id_index = re.search(file_id, url).end()
            key = url[id_index + 1:]
            return f'{file_id}!{key}'
        elif '!' in url:
            # V1 URL structure
            match = re.findall(r'/#!(.*)', url)
            path = match[0]
            return path
        else:
            raise RequestError('Url key missing')
