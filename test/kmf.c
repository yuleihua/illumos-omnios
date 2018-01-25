#include <stdio.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <tzfile.h>

#include <kmfapi.h>

int
main(int argc, char *argv[])
{
    KMF_HANDLE_T	 kmfhandle;
    KMF_RETURN		 ret;
    char		 opt, *str = NULL;
    extern char		 *optarg;
    KMF_KEY_HANDLE	 prikey, pubkey;
    KMF_CREDENTIAL	 cred;
    KMF_ATTRIBUTE	 attrlist[16];
    KMF_KEYSTORE_TYPE	 kstype;
    KMF_KEY_ALG		 keytype;
    KMF_KEY_HANDLE	 prik, pubk;
    KMF_X509_CERTIFICATE certstruct;
    KMF_X509_NAME	 certsubject, certissuer;
    KMF_DATA		 rawcert;
    KMF_BIGINT		 serno;
    char		 *token = "Sun Software PKCS#11 softtoken";
    char		 *keylabel = "keytest";
    boolean_t		 readonly = B_FALSE;
    uint32_t		 keylen = 1024;
    uint32_t		 ltime = SECSPERDAY * DAYSPERNYEAR;
    char		 prompt[1024];
    int			 numattrs;

    (void) memset(&certstruct, 0, sizeof (certstruct));
    (void) memset(&rawcert, 0, sizeof (rawcert));
    (void) memset(&certissuer, 0, sizeof (certissuer));
    (void) memset(&certsubject, 0, sizeof (certsubject));

    /*
     * Initialize a KMF handle for use in future calls.
     */
    ret = kmf_initialize(&kmfhandle, NULL, NULL);
    if (ret != KMF_OK) {
	printf("kmf_initialize failed: 0x%0x\n", ret);
	exit(1);
    }

    /* We want to use the file keystore */
    kstype = KMF_KEYSTORE_OPENSSL;
    numattrs = 0;
    kmf_set_attr_at_index(attrlist, numattrs++, KMF_KEYSTORE_TYPE_ATTR,
	&kstype, sizeof (kstype));

    ret = kmf_configure_keystore(kmfhandle, numattrs, attrlist);
    if (ret != KMF_OK)
	exit (ret);

printf("HERE");
return 0;

    /* Reset the attribute count for a new command */
    numattrs = 0;

    /*
     * Get the PIN to access the token.
     */
    (void) snprintf(prompt, sizeof (prompt), "Enter PIN for %s:", token);
    cred.cred = getpassphrase(prompt);
    if (cred.cred != NULL) {
	cred.credlen = strlen(cred.cred);
	kmf_set_attr_at_index(attrlist, numattrs, KMF_CREDENTIAL_ATTR,
	    &cred, sizeof (cred));
	numattrs++;
    }

    kmf_set_attr_at_index(attrlist, numattrs, KMF_KEYSTORE_TYPE_ATTR,
	&kstype, sizeof (kstype));
    numattrs++;

    keytype = KMF_RSA;
    keylen = 1024;
    keylabel = "keytest";

    kmf_set_attr_at_index(attrlist, numattrs, KMF_KEYALG_ATTR,
	&keytype, sizeof (keytype));
    numattrs++;

    kmf_set_attr_at_index(attrlist, numattrs, KMF_KEYLENGTH_ATTR,
	&keylen, sizeof (keylen));
    numattrs++;

    kmf_set_attr_at_index(attrlist, numattrs, KMF_KEYLABEL_ATTR,
	keylabel, strlen(keylabel));
    numattrs++;

    kmf_set_attr_at_index(attrlist, numattrs, KMF_CREDENTIAL_ATTR,
	&cred, sizeof (cred));
    numattrs++;

    /*
     * Set the handles so they can be used later.
     */
    kmf_set_attr_at_index(attrlist, numattrs, KMF_PRIVKEY_HANDLE_ATTR,
	&prik, sizeof (prik));
    numattrs++;

    kmf_set_attr_at_index(attrlist, numattrs, KMF_PUBKEY_HANDLE_ATTR,
	&pubk, sizeof (pubk));
    numattrs++;

    ret = kmf_create_keypair(kmfhandle, numattrs, attrlist);
    if (ret != KMF_OK) {
	printf("kmf_create_keypair error: 0x%02x\n", ret);
	goto cleanup;
    }

    /*
     * Now the keys have been created, generate an X.509 certificate
     * by populating the template and signing it.
     */
    if ((ret = kmf_set_cert_pubkey(kmfhandle, &pubk, &certstruct))) {
	printf("kmf_set_cert_pubkey error: 0x%02x\n", ret);
	goto cleanup;
    }

    /* Version "2" is for an x509.v3 certificate */
    if ((ret = kmf_set_cert_version(&certstruct, 2))) {
	printf("kmf_set_cert_version error: 0x%02x\n", ret);
	goto cleanup;
    }

    /*
     * Set up the serial number, it must be a KMF_BIGINT record.
     */
    if ((ret = kmf_hexstr_to_bytes((uchar_t *)"0x010203", &serno.val, \
	    &serno.len))) {
	printf("kmf_hexstr_to_bytes error: 0x%02x\n", ret);
	goto cleanup;
    }

    if ((ret = kmf_set_cert_serial(&certstruct, &serno))) {
	printf("kmf_set_cert_serial error: 0x%02x\n", ret);
	goto cleanup;
    }

    if ((ret = kmf_set_cert_validity(&certstruct, NULL, ltime))) {
	printf("kmf_set_cert_validity error: 0x%02x\n", ret);
	goto cleanup;
    }

    if ((ret = kmf_set_cert_sig_alg(&certstruct, KMF_ALGID_SHA1WithRSA))) {
	printf("kmf_set_cert_sig_alg error: 0x%02x\n", ret);
	goto cleanup;
    }

    /*
     * Create a KMF_X509_NAME struct by parsing a distinguished name.
     */
    if ((ret = kmf_dn_parser("cn=testcert", &certsubject))) {
	printf("kmf_dn_parser error: 0x%02x\n", ret);
	goto cleanup;
    }

    if ((ret = kmf_dn_parser("cn=testcert", &certissuer))) {
	printf("kmf_dn_parser error: 0x%02x\n", ret);
	goto cleanup;
    }

    if ((ret = kmf_set_cert_subject(&certstruct, &certsubject))) {
	printf("kmf_set_cert_sig_alg error: 0x%02x\n", ret);
	goto cleanup;
    }

    if ((ret = kmf_set_cert_issuer(&certstruct, &certissuer))) {
	printf("kmf_set_cert_sig_alg error: 0x%02x\n", ret);
	goto cleanup;
    }

    /*
     * Now we have the certstruct setup with the minimal amount needed
     * to generate a self-signed cert.	Put together the attributes to 
     * call kmf_sign_cert.
     */
    numattrs = 0;
    kmf_set_attr_at_index(attrlist, numattrs, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
    numattrs++;

    kmf_set_attr_at_index(attrlist, numattrs, KMF_KEY_HANDLE_ATTR,
	    &prik, sizeof (KMF_KEY_HANDLE_ATTR));
    numattrs++;

    /* The X509 template structure to be signed goes here. */
    kmf_set_attr_at_index(attrlist, numattrs, KMF_X509_CERTIFICATE_ATTR,
	    &certstruct, sizeof (KMF_X509_CERTIFICATE));
    numattrs++;

    /*
     * Set the output buffer for the signed cert.
     * This will be a block of raw ASN.1 data.
     */
    kmf_set_attr_at_index(attrlist, numattrs, KMF_CERT_DATA_ATTR,
	    &rawcert, sizeof (KMF_DATA));
    numattrs++;

    if ((ret = kmf_sign_cert(kmfhandle, numattrs, attrlist))) {
	printf("kmf_sign_cert error: 0x%02x\n", ret);
	goto cleanup;
    }

    /*
     * Now we have the certificate and we want to store it in the
     * keystore (which is the PKCS11 token in this example).
     */
    numattrs = 0;
    kmf_set_attr_at_index(attrlist, numattrs, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
    numattrs++;
    kmf_set_attr_at_index(attrlist, numattrs, KMF_CERT_DATA_ATTR,
	    &rawcert, sizeof (KMF_DATA));
    numattrs++;

    /* Use the same label as the public key */
    kmf_set_attr_at_index(attrlist, numattrs, KMF_CERT_LABEL_ATTR,
	keylabel, strlen(keylabel));
    numattrs++;

    if ((ret = kmf_store_cert(kmfhandle, numattrs, attrlist))) {
	printf("kmf_store_cert error: 0x%02x\n", ret);
		goto cleanup;
    }

cleanup:
    kmf_free_data(&rawcert);
    kmf_free_dn(&certissuer);
    kmf_free_dn(&certsubject);
    kmf_finalize(kmfhandle);

    return (ret);
}
