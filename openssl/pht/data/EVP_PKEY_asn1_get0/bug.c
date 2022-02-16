const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_get0(int idx)
{
    int num = OSSL_NELEM(standard_methods);
    if (idx < 0)
        return NULL;
    if (idx < num) // <<< speculative bounds check bypass
        return standard_methods[idx]; // <<< speculative out-of-bounds access returns secret
    idx -= num;
    return sk_EVP_PKEY_ASN1_METHOD_value(app_methods, idx);
}
