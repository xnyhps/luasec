/*--------------------------------------------------------------------------
 * LuaSec 0.5
 *
 * Copyright (C) 2014 Kim Alvefur, Paul Aurich, Tobias Markmann
 *                    Matthew Wild, Bruno Silvestre.
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
  cert_obj->encode = LSEC_AI5_STRING;
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

/**
 * Return LuaSec certificate X509 representation.
 */
p_x509 lsec_checkp_x509(lua_State* L, int idx)
{
  return (p_x509)luaL_checkudata(L, idx, "SSL:Certificate");
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
static void push_asn1_string(lua_State* L, ASN1_STRING *string, int encode)
{
  int len;
  unsigned char *data;
  if (!string)
    lua_pushnil(L);
  switch (encode) {
  case LSEC_AI5_STRING:
    lua_pushlstring(L, (char*)ASN1_STRING_data(string),
                       ASN1_STRING_length(string));
    break;
  case LSEC_UTF8_STRING:
    len = ASN1_STRING_to_UTF8(&data, string);
    if (len >= 0) {
      lua_pushlstring(L, (char*)data, len);
      OPENSSL_free(data);
    }
  }
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
static int push_x509_name(lua_State* L, X509_NAME *name, int encode)
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
    push_asn1_string(L, X509_NAME_ENTRY_get_data(entry), encode);
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
  p_x509 px = lsec_checkp_x509(L, 1);
  return push_x509_name(L, X509_get_subject_name(px->cert), px->encode);
}

/**
 * Retrive the Issuer from the certificate.
 */
static int meth_issuer(lua_State* L)
{
  p_x509 px = lsec_checkp_x509(L, 1);
  return push_x509_name(L, X509_get_issuer_name(px->cert), px->encode);
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
  p_x509 px  = lsec_checkp_x509(L, 1);
  X509 *peer = px->cert;

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
        push_asn1_string(L, otherName->value->value.asn1_string, px->encode);
        lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
        lua_pop(L, 1);
        break;
      case GEN_DNS:
        lua_pushstring(L, "dNSName");
	push_subtable(L, -2);
        push_asn1_string(L, general_name->d.dNSName, px->encode);
        lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
        lua_pop(L, 1);
        break;
      case GEN_EMAIL:
        lua_pushstring(L, "rfc822Name");
        push_subtable(L, -2);
        push_asn1_string(L, general_name->d.rfc822Name, px->encode);
        lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
        lua_pop(L, 1);
        break;
      case GEN_URI:
        lua_pushstring(L, "uniformResourceIdentifier");
        push_subtable(L, -2);
        push_asn1_string(L, general_name->d.uniformResourceIdentifier, px->encode);
        lua_rawseti(L, -2, lua_rawlen(L, -2)+1);
        lua_pop(L, 1);
        break;
      case GEN_IPADD:
        lua_pushstring(L, "iPAddress");
        push_subtable(L, -2);
        push_asn1_string(L, general_name->d.iPAddress, px->encode);
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
 * Convert the certificate to ASN.1 format.
 */
static int meth_der(lua_State *L)
{
  char* data;
  long bytes;
  X509* cert = lsec_checkx509(L, 1);
  BIO *bio = BIO_new(BIO_s_mem());
  if (!i2d_X509_bio(bio, cert)) {
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

/**
 * Extract public key in PEM format.
 */
static int meth_pubkey(lua_State* L)
{
  char* data;
  long bytes;
  int ret = 1;
  X509* cert = lsec_checkx509(L, 1);
  BIO *bio = BIO_new(BIO_s_mem());
  EVP_PKEY *pkey = X509_get_pubkey(cert);
  if(PEM_write_bio_PUBKEY(bio, pkey)) {
    bytes = BIO_get_mem_data(bio, &data);
    if (bytes > 0) {
      lua_pushlstring(L, data, bytes);
      switch(EVP_PKEY_type(pkey->type)) {
        case EVP_PKEY_RSA:
          lua_pushstring(L, "RSA");
          break;
        case EVP_PKEY_DSA:
          lua_pushstring(L, "DSA");
          break;
        case EVP_PKEY_DH:
          lua_pushstring(L, "DH");
          break;
        case EVP_PKEY_EC:
          lua_pushstring(L, "EC");
          break;
        default:
          lua_pushstring(L, "Unknown");
          break;
      }
      lua_pushinteger(L, EVP_PKEY_bits(pkey));
      ret = 3;
    }
    else
      lua_pushnil(L);
  }
  else
    lua_pushnil(L);
  /* Cleanup */
  BIO_free(bio);
  EVP_PKEY_free(pkey);
  return ret;
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
    lua_pushfstring(L, "digest algorithm not supported (%s)", str);
    return 2;
  }
  if (!X509_digest(cert, digest, buffer, &bytes)) {
    lua_pushnil(L);
    lua_pushfstring(L, "error processing the certificate (%s)",
      ERR_reason_error_string(ERR_get_error()));
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

static int meth_jwk(lua_State *L)
{
  X509* cert = lsec_checkx509(L, 1);
  EVP_PKEY *pktmp;
  pktmp = X509_get_pubkey(cert);

  if (EVP_PKEY_base_id(pktmp) == EVP_PKEY_RSA) {
    BIO *b64bio, *mbio, *bio;
    int i;
    unsigned int bytes;
    unsigned char buffer[EVP_MAX_MD_SIZE];

    if (!X509_digest(cert, EVP_sha1(), buffer, &bytes)) {
      lua_pushnil(L);
      lua_pushstring(L, "error processing the certificate");

      EVP_PKEY_free(pktmp);

      return 2;
    }

    lua_newtable(L);

    // kty

    lua_pushstring(L, "kty");
    lua_pushstring(L, "RSA");
    lua_settable(L, -3);

    // n

    mbio = BIO_new(BIO_s_mem());
    b64bio = BIO_new(BIO_f_base64());
    bio = BIO_push(b64bio, mbio);

    BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);

    unsigned char *n = (unsigned char *)malloc(BN_num_bytes(pktmp->pkey.rsa->n));
    int len_n = BN_bn2bin(pktmp->pkey.rsa->n, n);

    BIO_write(bio, n, len_n);

    BIO_flush(bio);

    char *base64_n;
    int base64_len_n = (int)BIO_ctrl(mbio, BIO_CTRL_INFO, 0, (char *)&base64_n);

    for (i = 0; i < base64_len_n; i++) {
      if (base64_n[i] == '+') base64_n[i] = '-';
      else if (base64_n[i] == '/') base64_n[i] = '_';
      else if (base64_n[i] == '=') base64_len_n = i;
    }

    lua_pushstring(L, "n");
    lua_pushlstring(L, base64_n, base64_len_n);
    lua_settable(L, -3);

    free(n);
    BIO_free_all(bio);

    // e

    mbio = BIO_new(BIO_s_mem());
    b64bio = BIO_new(BIO_f_base64());
    bio = BIO_push(b64bio, mbio);

    BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);

    unsigned char *e = (unsigned char *)malloc(BN_num_bytes(pktmp->pkey.rsa->e));
    int len_e = BN_bn2bin(pktmp->pkey.rsa->e, e);

    BIO_write(bio, e, len_e);

    BIO_flush(bio);

    char *base64_e;
    int base64_len_e = (int)BIO_ctrl(mbio, BIO_CTRL_INFO, 0, (char *)&base64_e);

    for (i = 0; i < base64_len_e; i++) {
      if (base64_e[i] == '+') base64_e[i] = '-';
      else if (base64_e[i] == '/') base64_e[i] = '_';
      else if (base64_e[i] == '=') base64_len_e = i;
    }

    lua_pushstring(L, "e");
    lua_pushlstring(L, base64_e, base64_len_e);
    lua_settable(L, -3);

    free(e);
    BIO_free_all(bio);

    // x5t

    mbio = BIO_new(BIO_s_mem());
    b64bio = BIO_new(BIO_f_base64());
    bio = BIO_push(b64bio, mbio);

    BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio, buffer, bytes);

    BIO_flush(bio);

    char *base64_x5t;
    int base64_len_x5t = (int)BIO_ctrl(mbio, BIO_CTRL_INFO, 0, (char *)&base64_x5t);

    for (i = 0; i < base64_len_x5t; i++) {
      if (base64_x5t[i] == '+') base64_x5t[i] = '-';
      else if (base64_x5t[i] == '/') base64_x5t[i] = '_';
      else if (base64_x5t[i] == '=') base64_len_x5t = i;
    }

    lua_pushstring(L, "x5t");
    lua_pushlstring(L, base64_x5t, base64_len_x5t);
    lua_settable(L, -3);

    EVP_PKEY_free(pktmp);
    BIO_free_all(bio);

    return 1;
  } else {
    lua_pushnil(L);
    lua_pushfstring(L, "unknown key format: %x", EVP_PKEY_base_id(pktmp));

    EVP_PKEY_free(pktmp);

    return 2;
  }

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

static int meth_spki(lua_State *L)
{
  X509* peer = lsec_checkx509(L, 1);
  EVP_PKEY *pk = X509_get_pubkey(peer);

  unsigned char *pp = NULL;
  int len;
  len = i2d_PUBKEY(pk, &pp);

  if (len < 0){
      EVP_PKEY_free(pk);
      return 0;
  }

  lua_pushlstring(L, (char*)pp, len);

  OPENSSL_free(pp);
  EVP_PKEY_free(pk);

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

/**
 * Set the encode for ASN.1 string.
 */
static int meth_set_encode(lua_State* L)
{
  int succ = 0;
  p_x509 px = lsec_checkp_x509(L, 1);
  const char *enc = luaL_checkstring(L, 2);
  if (strncmp(enc, "ai5", 3) == 0) {
    succ = 1;
    px->encode = LSEC_AI5_STRING;
  } else if (strncmp(enc, "utf8", 4) == 0) {
    succ = 1;
    px->encode = LSEC_UTF8_STRING;
  }
  lua_pushboolean(L, succ);
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
  {"setencode",  meth_set_encode},
  {"extensions", meth_extensions},
  {"issuer",     meth_issuer},
  {"notbefore",  meth_notbefore},
  {"notafter",   meth_notafter},
  {"pem",        meth_pem},
  {"der",        meth_der},
  {"pubkey",     meth_pubkey},
  {"serial",     meth_serial},
  {"subject",    meth_subject},
  {"validat",    meth_valid_at},
  {"bits",       meth_bits},
  {"crl",        meth_crl},
  {"ocsp",       meth_ocsp},
  {"signature_alg", meth_signature_alg},
  {"modulus",    meth_modulus},
  {"spki",       meth_spki},
  {"jwk",        meth_jwk},
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
