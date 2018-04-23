import pyshark
import MasterDecrypter
from Cryptodome.Cipher import AES

"""
Carve relevant TLS info out of pcap. Pcap must contain a single TLS session
"""
CONTENT_APPLICATION_DATA = b'\x17'
CONTENT_HANDSHAKE = b'\x16'
HANDSHAKE_CLIENT_HELLO = b'\x01'
HANDSHAKE_SERVER_HELLO = b'\x02'

packets = pyshark.FileCapture('singlestream.openmrs.org.pcap')

client_random = None
server_random = None
ciphersuite = None

for idx, packet in enumerate(packets):
    if 'SSL' not in packet:
        #print('Discarding non-ssl packet: #{}'.format(idx))
        pass
    elif hasattr(packet.ssl, 'record_content_type'):

        if hasattr(packet.ssl, 'handshake_type'):
            if packet.ssl.record_content_type.binary_value == CONTENT_HANDSHAKE and \
                            packet.ssl.handshake_type.binary_value == HANDSHAKE_CLIENT_HELLO:
                print('Reading client hello from packet: #{}'.format(idx))
                print('Got Client Random: {}'.format(packet.ssl.handshake_random))
                client_random = packet.ssl.handshake_random.binary_value

            elif packet.ssl.record_content_type.binary_value == CONTENT_HANDSHAKE and \
                            packet.ssl.handshake_type.binary_value == HANDSHAKE_SERVER_HELLO:
                print('Reading server hello from packet: #{}'.format(idx))
                print('Got Server Random: {}'.format(packet.ssl.handshake_random))
                print('Got {}'.format(packet.ssl.handshake_ciphersuite.showname))
                server_random = packet.ssl.handshake_random.binary_value
                ciphersuite = packet.ssl.handshake_ciphersuite.binary_value

        elif packet.ssl.record_content_type.binary_value == CONTENT_APPLICATION_DATA:
            print('Reading {} bytes encrypted application data from packet: #{}'.format(
                len(packet.ssl.app_data.binary_value),
                idx
            ))

if client_random is None or server_random is None or ciphersuite is None:
    print('Incomplete handshake, unable to decrypt')
    quit()
else:
    pass