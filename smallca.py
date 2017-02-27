#!/usr/bin/env python
# vim:ts=4

import sys, argparse
from OpenSSL import crypto

class SmallCa:

	def __init__(self):
		serial_no = 1

	def create_cert(self):
		cert = crypto.X509()
		#cert.set_serial_number(self.serial_no)
		#cert.gmtime_adj_notBefore(notBeforeVal)
		#cert.gmtime_adj_notAfter(notAfterVal)
		#cert.set_issuer(caCert.get_subject())
		#cert.set_subject(deviceCsr.get_subject())
		#cert.set_pubkey(deviceCsr.get_pubkey())
		#cert.sign(CAprivatekey, digest)
		return cert


    def run(self, argv):
        parser = argparse.ArgumentParser(description='Small certificate authority.')
        parser.add_argument('--base-dir',
                help='Use different base directory')
        parser.add_argument('--init',
                action='store_true',
                help='Initialize new CA. WARNING! Existing CA will be destroyed!')
        args = parser.parse_args(argv)
        parser.print_help()

        cert = self.create_cert();
        print(cert)


if __name__ == "__main__":
    ca = SmallCa()
    ca.run(sys.argv[1:])
