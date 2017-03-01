#!/usr/bin/env python
# vim:ts=4

import os, sys, time, argparse, ConfigParser
from OpenSSL import crypto


class CaConfig:

	def __init__(self):
		self.defIssuer = crypto.X509Name(crypto.X509().get_subject())
		self.defSubject = crypto.X509Name(crypto.X509().get_subject())
		self.caValidityPeriod = 20 * 365 * 86400
		self.validityPeriod = 2 * 365 * 86400

	def readConfig(self, conf_file):
		config = ConfigParser.ConfigParser()
		config.optionxform = str # TODO deal with case sensitive OBJ_txt2nid
		config.read(conf_file)
		self.defIssuer = self.getX509Name(config, 'issuer')
		self.defSubject = self.getX509Name(config, 'subject')

	def getX509Name(self, config, section):
		dn = crypto.X509Name(crypto.X509().get_subject())
		if config.has_section(section):
			for (name,val) in config.items(section):
				setattr(dn, name.upper(), val)
		return dn

	def setX509Name(self, parser, section, dn):
		config.add_section(section)
		for (name,val) in dn.get_components():
			config[section][name] = val



class SmallCa:

	def __init__(self):
		self.config = CaConfig()

	def inputDistinguishName(self, template):
		dn = crypto.X509Name(template)
		return dn

	def create_self_signed_cert(self):

		serialNumber = 1000

		issuer = self.inputDistinguishName(self.config.defIssuer)

		keyType = crypto.TYPE_RSA
		keyLength = 4096
		digestType = 'sha256'

    	# create a key pair
    	key = crypto.PKey()
    	key.generate_key(keyType, keyLength)

    	# create a self-signed cert
    	cert = crypto.X509()
    	cert.set_serial_number(1000)
    	cert.gmtime_adj_notBefore(0)
    	cert.gmtime_adj_notAfter(self.config.caValidityPeriod)
    	cert.set_issuer(issuer)
		cert.set_subject(issuer)
    	cert.set_pubkey(key)
    	cert.sign(key, digestType)

		return cert

    	# open(join(cert_dir, CERT_FILE), "wt").write(
        # 	crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    	# open(join(cert_dir, KEY_FILE), "wt").write(
        # 	crypto.dump_privatekey(crypto.FILETYPE_PEM, k))


	# def create_cert(self):
	#
    #     serial_no = 1;
    #     notBefore = gmtime()
    #     notAfter = notBefore + 365 * 86400
	#
	# 	cert = crypto.X509
	# 	cert.set_serial_number(self.serial_no)
	# 	cert.gmtime_adj_notBefore(notBefore)
	# 	cert.gmtime_adj_notAfter(notAfter)
	# 	#cert.set_issuer(caCert.get_subject())
	# 	#cert.set_subject(deviceCsr.get_subject())
	# 	#cert.set_pubkey(deviceCsr.get_pubkey())
	# 	#cert.sign(CAprivatekey, digest)
	# 	return cert


    def run(self, argv):
        # parser = argparse.ArgumentParser(description='Small certificate authority.')
        # parser.add_argument('--base-dir',
        #         help='Use different base directory')
        # parser.add_argument('--init',
        #         action='store_true',
        #         help='Initialize new CA. WARNING! Existing CA will be destroyed!')
        # args = parser.parse_args(argv)
        # parser.print_help()

		conf_dir = os.path.expanduser("~") + "/.config/small-ca"
		conf_file = conf_dir + "/ca.ini"
		if not os.path.isfile(conf_file):
			if not os.path.isdir(conf_dir):
				os.makedirs(conf_dir, 0700)
			open(conf_file, 'a').close()

		self.config.readConfig(conf_file)
        cert = self.create_self_signed_cert();
        print(cert.get_subject())
        print(cert.get_issuer())
        print(cert.digest("sha256"))
        print(cert.get_notBefore())
        print(cert.get_notAfter())


if __name__ == "__main__":
    ca = SmallCa()
    ca.run(sys.argv[1:])
