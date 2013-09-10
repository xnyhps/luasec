/*--------------------------------------------------------------------------
 * LuaSec 0.4.1
 * Copyright (C) 2012
 *
 *--------------------------------------------------------------------------*/

#include <string.h>

#if defined(WIN32)
#include <windows.h>
#endif

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

#include <lua.h>
#include <lauxlib.h>

#include "x509.h"

static const char* hex_tab = "0123456789abcdef";

/**
 * Push the certificate on the stack.
 */
void lsec_pushx509(lua_State* L, X509 *cert)
{
  p_x509 cert_obj = (p_x509)lua_newuserdata(L, sizeof(t_x509));
  cert_obj->cert = cert;
  luaL_getmetatable(L, "SSL:Certificate");
  lua_setmetatable(L, -2);
}

/**
 * Return the OpenSSL certificate X509.
 */
X509* lsec_checkx509(lua_State* L, int idx)
{
  return ((p_x509)luaL_checkudata(L, idx, "SSL:Certificate"))->cert;
}

/*---------------------------------------------------------------------------*/

/**
 * Convert the buffer 'in' to hexadecimal.
 */
static void to_hex(const char* in, int length, char* out)
{
  int i;
  for (i = 0; i < length; i++) {
    out[i*2] = hex_tab[(in[i] >> 4) & 0xF];
    out[i*2+1] = hex_tab[(in[i]) & 0xF];
  }
}

/**
 * Converts the ASN1_OBJECT into a textual representation and put it
 * on the Lua stack.
 */
static void push_asn1_objname(lua_State* L, ASN1_OBJECT *object, int no_name)
{
  char buffer[256];
  int len = OBJ_obj2txt(buffer, sizeof(buffer), object, no_name);
  len = (len < sizeof(buffer)) ? len : sizeof(buffer);
  lua_pushlstring(L, buffer, len);
}

/**
 * Push the ASN1 string on the stack.
 */
static void push_asn1_string(lua_State* L, ASN1_STRING *string)
{
  if (string)
    lua_pushlstring(L, (char*)ASN1_STRING_data(string),
                       ASN1_STRING_length(string));
  else
    lua_pushnil(L);
}

/**
 * Return a human readable time.
 */
static int push_asn1_time(lua_State *L, ASN1_UTCTIME *tm)
{
  char *tmp;
  long size;
  BIO *out = BIO_new(BIO_s_mem());
  ASN1_TIME_print(out, tm);
  size = BIO_get_mem_data(out, &tmp);
  lua_pushlstring(L, tmp, size);
  BIO_free(out);
  return 1;
}

/**
 * 
 */
static int push_subtable(lua_State* L, int idx)
{
  lua_pushvalue(L, -1);
  lua_gettable(L, idx-1);
  if (lua_isnil(L, -1)) {
    lua_pop(L, 1);
    lua_newtable(L);
    lua_pushvalue(L, -2);
    lua_pushvalue(L, -2);
    lua_settable(L, idx-3);
    lua_replace(L, -2); /* Replace key with table */
    return 1;
  }
  lua_replace(L, -2); /* Replace key with table */
  return 0;
}

/**
 * Retrive the general names from the object.
 */
static int push_x509_name(lua_State* L, X509_NAME *name)
{
  int i;
  int n_entries;
  ASN1_OBJECT *object;
  X509_NAME_ENTRY *entry;
  lua_newtable(L);
  n_entries = X509_NAME_entry_count(name);
  for (i = 0; i < n_entries; i++) {
    entry = X509_NAME_get_entry(name, i);
    object = X509_NAME_ENTRY_get_object(entry);
    lua_newtable(L);
    push_asn1_objname(L, object, 1);
    lua_setfield(L, -2, "oid");
    push_asn1_objname(L, object, 0);
    lua_setfield(L, -2, "name");
    push_asn1_string(L, X509_NAME_ENTRY_get_data(entry));
    lua_setfield(L, -2, "value");
    lua_rawseti(L, -2, i+1);
  }
  return 1;
}

/*---------------------------------------------------------------------------*/

/**
 * Retrive the Subject from the certificate.
 */
static int meth_subject(lua_State* L)
{
  return push_x509_name(L, X509_get_subject_name(lsec_checkx509(L, 1)));
}

/**
 * Retrive the Issuer from the certificate.
 */
static int meth_issuer(lua_State* L)
{
  return push_x509_name(L, X509_get_issuer_name(lsec_checkx509(L, 1)));
}

/**
 * Retrieve the extensions from the certificate.
 */
int meth_extensions(lua_State* L)
{
  int j;
  int i = -1;
  int n_general_names;
  OTHERNAME *otherName;
  X509_EXTENSION *extension;
  GENERAL_NAME *general_name;
  STACK_OF(GENERAL_NAME) *values;
  X509 *peer = lsec_checkx509(L, 1);

  /* Return (ret) */
  lua_newtable(L);

  while ((i = X509_get_ext_by_NID(peer, NID_subject_alt_name, i)) != -1) {
    extension = X509_get_ext(peer, i);
    if (extension == NULL)
      break;
    values = X509V3_EXT_d2i(extension);
    if (values == NULL)
      break;

    /* Push ret[oid] */
    push_asn1_objname(L, extension->object, 1);
    push_subtable(L, -2);

    /* Set ret[oid].name = name */
    push_asn1_objname(L, extension->object, 0);
    lua_setfield(L, -2, "name");

    n_general_names = sk_GENERAL_NAME_num(values);
    for (j = 0; j < n_general_names; j++) {
      general_name = sk_GENERAL_NAME_value(values, j);
      switch (general_name->type) {
      case GEN_OTHERNAME:
        otherName = general_name->d.otherName;
        push_asn1_objname(L, otherName->type_id, 1);
        if (push_subtable(L, -2)) {
          push_asn1_objname(L, otherName->type_id, 0);
          lua_setfield(L, -2, "name");
        }
        push_asn1_string(L, otherName->value->value.asn1_string);
        lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
        lua_pop(L, 1);
        break;
      case GEN_DNS:
        lua_pushstring(L, "dNSName");
	push_subtable(L, -2);
        push_asn1_string(L, general_name->d.dNSName);
        lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
        lua_pop(L, 1);
        break;
      case GEN_EMAIL:
        lua_pushstring(L, "rfc822Name");
        push_subtable(L, -2);
        push_asn1_string(L, general_name->d.rfc822Name);
        lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
        lua_pop(L, 1);
        break;
      case GEN_URI:
        lua_pushstring(L, "uniformResourceIdentifier");
        push_subtable(L, -2);
        push_asn1_string(L, general_name->d.uniformResourceIdentifier);
        lua_rawseti(L, -2, lua_rawlen(L, -2)+1);
        lua_pop(L, 1);
        break;
      case GEN_IPADD:
        lua_pushstring(L, "iPAddress");
        push_subtable(L, -2);
        push_asn1_string(L, general_name->d.iPAddress);
        lua_rawseti(L, -2, lua_rawlen(L, -2)+1);
        lua_pop(L, 1);
        break;
      case GEN_X400:
        /* x400Address   */
        /* not supported */
        break;
      case GEN_DIRNAME:
        /* directoryName */
        /* not supported */
        break;
      case GEN_EDIPARTY:
        /* ediPartyName */
        /* not supported */
        break;
      case GEN_RID:
        /* registeredID  */
        /* not supported */
        break;
      }
    }
    lua_pop(L, 1); /* ret[oid] */
    i++;           /* Next extension */
  }
  return 1;
}

/**
 * Convert the certificate to PEM format.
 */
static int meth_pem(lua_State* L)
{
  char* data;
  long bytes;
  X509* cert = lsec_checkx509(L, 1);
  BIO *bio = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_X509(bio, cert)) {
    lua_pushnil(L);
    return 1;
  }
  bytes = BIO_get_mem_data(bio, &data);
  if (bytes > 0)
    lua_pushlstring(L, data, bytes);
  else
    lua_pushnil(L);
  BIO_free(bio);
  return 1;
}

/**
 * Compute the fingerprint.
 */
static int meth_digest(lua_State* L)
{
  unsigned int bytes;
  const EVP_MD *digest = NULL;
  unsigned char buffer[EVP_MAX_MD_SIZE];
  char hex_buffer[EVP_MAX_MD_SIZE*2];
  X509 *cert = lsec_checkx509(L, 1);
  const char *str = luaL_optstring(L, 2, NULL);
  if (!str)
    digest = EVP_sha1();
  else {
    if (!strcmp(str, "sha1"))
      digest = EVP_sha1();
    else if (!strcmp(str, "sha256"))
      digest = EVP_sha256();
    else if (!strcmp(str, "sha512"))
      digest = EVP_sha512();
  }
  if (!digest) {
    lua_pushnil(L);
    lua_pushstring(L, "digest algorithm not supported");
    return 2;
  }
  if (!X509_digest(cert, digest, buffer, &bytes)) {
    lua_pushnil(L);
    lua_pushstring(L, "error processing the certificate");
    return 2;
  }
  to_hex((char*)buffer, bytes, hex_buffer);
  lua_pushlstring(L, hex_buffer, bytes*2);
  return 1;
}

/**
 * Retrieve the number of bits of the key
 */
static int meth_bits(lua_State* L)
{
  int bits = -1;
  X509* cert = lsec_checkx509(L, 1);
  EVP_PKEY *pktmp;
  pktmp = X509_get_pubkey(cert);
  bits = EVP_PKEY_bits(pktmp);
  EVP_PKEY_free(pktmp);
  lua_pushinteger(L, bits);
  return 1;
}

static int meth_modulus(lua_State* L)
{
  X509* cert = lsec_checkx509(L, 1);
  EVP_PKEY *pktmp;
  pktmp = X509_get_pubkey(cert);

  if (EVP_PKEY_base_id(pktmp) == EVP_PKEY_RSA) {
    char *tmp = BN_bn2hex(pktmp->pkey.rsa->n);
    lua_pushstring(L, tmp);

    OPENSSL_free(tmp);
    EVP_PKEY_free(pktmp);

    return 1;
  }

  EVP_PKEY_free(pktmp);

  return 0;
}

/**
 * Check if the certificate is valid in a given time.
 */
static int meth_valid_at(lua_State* L)
{
  X509* cert = lsec_checkx509(L, 1);
  time_t time = luaL_checkinteger(L, 2);
  lua_pushboolean(L, (X509_cmp_time(X509_get_notAfter(cert), &time)     >= 0
                      && X509_cmp_time(X509_get_notBefore(cert), &time) <= 0));
  return 1;
}

/**
 * Return the serial number.
 */
static int meth_serial(lua_State *L)
{
  char *tmp;
  BIGNUM *bn;
  ASN1_INTEGER *serial;
  X509* cert = lsec_checkx509(L, 1);
  serial = X509_get_serialNumber(cert);
  bn = ASN1_INTEGER_to_BN(serial, NULL);
  tmp = BN_bn2hex(bn);
  lua_pushstring(L, tmp);
  BN_free(bn);
  OPENSSL_free(tmp);
  return 1;
}

/**
 * Return not before date.
 */
static int meth_notbefore(lua_State *L)
{
  X509* cert = lsec_checkx509(L, 1);
  return push_asn1_time(L, X509_get_notBefore(cert));
}

/**
 * Return not after date.
 */
static int meth_notafter(lua_State *L)
{
  X509* cert = lsec_checkx509(L, 1);
  return push_asn1_time(L, X509_get_notAfter(cert));
}

static int meth_crl(lua_State *L)
{
  X509* peer = lsec_checkx509(L, 1);
  STACK_OF(DIST_POINT) *dps = X509_get_ext_d2i(peer, NID_crl_distribution_points, NULL, NULL);
  DIST_POINT *dp;
  STACK_OF(GENERAL_NAME) *names;
  GENERAL_NAME *name;

  if (dps == NULL || sk_DIST_POINT_num(dps) == 0) {
    lua_pushnil(L);
    return 1;
  }

  dp = sk_DIST_POINT_pop(dps);
  names = dp->distpoint->name.fullname;

  if (sk_GENERAL_NAME_num(names) == 0) {
    lua_pushnil(L);
    return 1;
  }

  name = sk_GENERAL_NAME_pop(names);
  if (name->type == GEN_URI) {
      push_asn1_string(L, name->d.uniformResourceIdentifier);
      return 1;
  } else {
      lua_pushnil(L);
      return 1;
  }
}

static int meth_ocsp(lua_State *L)
{
  X509* peer = lsec_checkx509(L, 1);
  AUTHORITY_INFO_ACCESS *info;
  int i, count = 0;

  info = X509_get_ext_d2i(peer, NID_info_access, NULL, NULL);

  if (info == NULL) {
    lua_pushnil(L);
    return 1;
  }

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++) {
    ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(info, i);

    if (OBJ_obj2nid(ad->method) == NID_ad_OCSP) {
      if (ad->location->type == GEN_URI) {
        push_asn1_string(L, ad->location->d.uniformResourceIdentifier);
        count++;
      }
    }
  }

  AUTHORITY_INFO_ACCESS_free(info);

  return count;
}

static int meth_signature_alg(lua_State *L)
{
  X509* peer = lsec_checkx509(L, 1);

  push_asn1_objname(L, peer->sig_alg->algorithm, 0);

  return 1;
}

/**
 * Collect X509 objects.
 */
static int meth_destroy(lua_State* L)
{
  X509_free(lsec_checkx509(L, 1));
  return 0;
}

static int meth_tostring(lua_State *L)
{
  X509* cert = lsec_checkx509(L, 1);
  lua_pushfstring(L, "X509 certificate: %p", cert);
  return 1;
}

/*---------------------------------------------------------------------------*/

static int load_cert(lua_State* L)
{
  X509 *cert;
  size_t bytes;
  const char* data;
  BIO *bio = BIO_new(BIO_s_mem());
  data = luaL_checklstring(L, 1, &bytes);
  BIO_write(bio, data, bytes);
  cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  if (cert)
    lsec_pushx509(L, cert);
  else
    lua_pushnil(L);
  BIO_free(bio);
  return 1;
}

/*---------------------------------------------------------------------------*/

/**
 * Certificate methods.
 */
static luaL_Reg methods[] = {
  {"digest",     meth_digest},
  {"extensions", meth_extensions},
  {"issuer",     meth_issuer},
  {"notbefore",  meth_notbefore},
  {"notafter",   meth_notafter},
  {"pem",        meth_pem},
  {"serial",     meth_serial},
  {"subject",    meth_subject},
  {"validat",    meth_valid_at},
  {"bits",       meth_bits},
  {"crl",        meth_crl},
  {"ocsp",       meth_ocsp},
  {"signature_alg", meth_signature_alg},
  {"modulus",    meth_modulus},
  {NULL,         NULL}
};

/**
 * X509 metamethods.
 */
static luaL_Reg meta[] = {
  {"__gc",       meth_destroy},
  {"__tostring", meth_tostring},
  {NULL, NULL}
};

/**
 * X509 functions.
 */
static luaL_Reg funcs[] = {
  {"load", load_cert},
  {NULL,   NULL}
};

/*--------------------------------------------------------------------------*/

#if (LUA_VERSION_NUM == 501)

LSEC_API int luaopen_ssl_x509(lua_State *L)
{
  /* Register the functions and tables */
  luaL_newmetatable(L, "SSL:Certificate");
  luaL_register(L, NULL, meta);

  lua_newtable(L);
  luaL_register(L, NULL, methods);
  lua_setfield(L, -2, "__index");

  luaL_register(L, "ssl.x509", funcs);

  return 1;
}

#else

LSEC_API int luaopen_ssl_x509(lua_State *L)
{
  /* Register the functions and tables */
  luaL_newmetatable(L, "SSL:Certificate");
  luaL_setfuncs(L, meta, 0);

  lua_newtable(L);
  luaL_setfuncs(L, methods, 0);
  lua_setfield(L, -2, "__index");

  lua_newtable(L);
  luaL_setfuncs(L, funcs, 0);

  return 1;
}

#endif
