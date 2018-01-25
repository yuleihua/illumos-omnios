#include <stdio.h>
#include <assert.h>
#include <ipsec_util.h>
#include <openssl/x509.h>

int
main()
{
	X509_NAME *a;
	unsigned char *buf;
	int len;

	a = X509_NAME_new();
	assert(a != NULL);
	assert(X509_NAME_add_entry_by_txt(a, "C", MBSTRING_ASC, 
	    "UK", -1, -1, 0) == 1);
	assert(X509_NAME_add_entry_by_txt(a, "O", MBSTRING_ASC,
	    "illumos org", -1, -1, 0) == 1);
	assert(X509_NAME_add_entry_by_txt(a, "CN", MBSTRING_ASC,
	    "Joe Bloggs", -1, -1, 0) == 1);

	buf = NULL;
	len = i2d_X509_NAME(a, &buf);
	assert(len > 1);
	X509_NAME_free(a);

	print_asn1_name(stdout, buf, len);

	OPENSSL_free(buf);

	return 0;
}

