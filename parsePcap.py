import pyshark
import MasterDecrypter
from Cryptodome.Cipher import AES
from Cryptodome import Hash

"""
Carve relevant TLS info out of pcap.

Assumptions:
- pcap contains only one tcp stream
- symmetric algorithm is AES
"""
CONTENT_APPLICATION_DATA = b'\x17'
CONTENT_HANDSHAKE = b'\x16'
HANDSHAKE_CLIENT_HELLO = b'\x01'
HANDSHAKE_SERVER_HELLO = b'\x02'

master_secret = b'\xd2\x76\x4f\x01\x83\x60\xd6\xc1\x29\x3c\x56\x76\xe2\x06\xad\xe5\x8b\x31\xfc\x56\x77\xde\xef\x2a\xee\xda\xb0\xf7\x28\x7d\x87\xea\x43\xb5\xc6\xd9\x9c\xd8\xc9\x01\x39\xb0\x7a\xbe\x6a\xe4\x99\xbc'


def cs_name_to_values(ciphersuite_name):
    symmetric_part = ciphersuite_name.split('WITH_')[1]

    enc_algo, size_raw, mode_raw, hash_raw = symmetric_part.split('_')
    size = int(size_raw)
    mode = getattr(AES, 'MODE_{}'.format(mode_raw))
    hash_str = hash_raw.split()[0]

    if hash_str == 'SHA384':
        hash_algo = Hash.SHA384
    elif hash_str == 'SHA256':
        hash_algo = Hash.SHA256
    elif hash_str == 'SHA1':
        hash_algo = Hash.SHA1
    elif hash_str == 'SHA224':
        hash_algo = Hash.SHA224
    elif hash_str == 'SHA512':
        hash_algo = Hash.SHA512
    else:
        raise ValueError('Unsupported hash: {}'.format(hash_str))

    return enc_algo, size, mode, hash_algo


packets = pyshark.FileCapture('singlestream.openmrs.org.pcap')

client_random = None
server_random = None
ciphersuite = None
application_datas_c2s = list()
application_datas_s2c = list()
client_addr = b''
server_addr = b''

for idx, packet in enumerate(packets):
    if 'SSL' not in packet:
        #print('Discarding non-ssl packet: #{}'.format(idx))
        pass
    elif hasattr(packet.ssl, 'record_content_type'):

        if hasattr(packet.ssl, 'handshake_type'):
            if packet.ssl.record_content_type.binary_value == CONTENT_HANDSHAKE and \
                            packet.ssl.handshake_type.binary_value == HANDSHAKE_CLIENT_HELLO:
                client_random = packet.ssl.handshake_random.binary_value
                client_addr = packet.ip.src_host
                print('Reading client hello from {} packet #{}'.format(client_addr, idx))
                print('Got Client Random: {}'.format(client_random))


            elif packet.ssl.record_content_type.binary_value == CONTENT_HANDSHAKE and \
                            packet.ssl.handshake_type.binary_value == HANDSHAKE_SERVER_HELLO:
                server_random = packet.ssl.handshake_random.binary_value
                ciphersuite = packet.ssl.handshake_ciphersuite.showname
                server_addr = packet.ip.src_host
                print('Reading server hello from {} packet #{}'.format(server_addr, idx))
                print('Got Server Random: {}'.format(server_random))
                print('Got {}'.format(ciphersuite))


        elif packet.ssl.record_content_type.binary_value == CONTENT_APPLICATION_DATA:
            print('Reading {} bytes encrypted application data from packet: #{}'.format(
                len(packet.ssl.app_data.binary_value),
                idx
            ))

            if packet.ip.src_host == server_addr:
                application_datas_s2c.append(packet.ssl.app_data.binary_value)
            elif packet.ip.src_host == client_addr:
                application_datas_c2s.append(packet.ssl.app_data.binary_value)

if client_random is None or server_random is None or ciphersuite is None:
    print('Incomplete handshake, unable to decrypt')
    quit()
elif len(application_datas_c2s) + len(application_datas_s2c) < 1:
    print('No application data found to decrypt')
    quit()

enc_algo, size, mode, hash_algo = cs_name_to_values(ciphersuite)
decrypter = MasterDecrypter.MasterDecrypter(size, mode, hash_algo, master_secret, server_random, client_random)

for record in application_datas_c2s:
    print(decrypter.decrypt_client(record))
