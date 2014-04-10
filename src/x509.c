/*--------------------------------------------------------------------------
 * LuaSec 0.5
 *
 * Copyright (C) 2014 Kim Alvefur, Paul Aurich, Tobias Markmann
 *                    Matthew Wild, Bruno Silvestre.
 *
 *--------------------------------------------------------------------------*/

#include <string.h>
#include <stdlib.h>
#include <time.h>

#if defined(WIN32)
#include <windows.h>
#endif

#include <lua.h>
#include <lauxlib.h>

#include <polarssl/base64.h>
#include <polarssl/oid.h>

#include "x509.h"

static const char* hex_tab = "0123456789abcdef";

/**
 * Push the certificate on the stack.
 */
void lsec_pushx509(lua_State* L, const x509_crt *cert)
{
  x509_crt *cert_obj = (x509_crt*)lua_newuserdata(L, sizeof(x509_crt));
  memcpy(cert_obj, cert, sizeof(x509_crt));
  luaL_getmetatable(L, "SSL:Certificate");
  lua_setmetatable(L, -2);
}

/**
 * Return the OpenSSL certificate X509.
 */
x509_crt* lsec_checkx509(lua_State* L, int idx)
{
  return ((x509_crt *)luaL_checkudata(L, idx, "SSL:Certificate"));
}

/**
 * Push the ASN1 string on the stack.
 */
static int push_x509_name(lua_State *L, x509_name *name)
{
  char oid[256];
  int i = 0;

  lua_newtable(L);

  while (name) {
    if (!name->oid.p) {
      name = name->next;
      continue;
    }

    if (oid_get_numeric_string(oid, 256, &name->oid) >= 0) {
      lua_newtable(L);
      lua_pushstring(L, oid);
      lua_setfield(L, -2, "oid");
      // lua_setfield(L, -2, "name");
      lua_pushlstring(L, (const char *)name->val.p, name->val.len);
      lua_setfield(L, -2, "value");
      lua_rawseti(L, -2, i+1);
    }

    i++;
    name = name->next;
  }

  return 1;
}

/**
 * Return a time as UNIX time.
 */
static time_t x509_time_to_time_t(x509_time *xtime)
{
  struct tm lt = {0};

  lt.tm_year = xtime->year - 1900;
  lt.tm_mon = xtime->mon - 1;
  lt.tm_mday = xtime->day;
  lt.tm_hour = xtime->hour;
  lt.tm_min = xtime->min;
  lt.tm_sec = xtime->sec;

  time_t tt = mktime(&lt);

  return tt;
}

/*---------------------------------------------------------------------------*/

/**
 * Retrive the Subject from the certificate.
 */
static int meth_subject(lua_State* L)
{
  x509_crt *cert = lsec_checkx509(L, 1);
  return push_x509_name(L, &cert->subject);
}

/**
 * Retrive the Issuer from the certificate.
 */
static int meth_issuer(lua_State* L)
{
  x509_crt *cert = lsec_checkx509(L, 1);
  return push_x509_name(L, &cert->issuer);
}

/**
 * Retrieve the extensions from the certificate.
 */
static int meth_extensions(lua_State* L)
{
  x509_crt *cert = lsec_checkx509(L, 1);

  lua_newtable(L);

  return 1;
}

/**
 * Check if the certificate is valid in a given time.
 */
static int meth_valid_at(lua_State* L)
{
  x509_crt* cert = lsec_checkx509(L, 1);
  time_t tt = luaL_checkinteger(L, 2);
  time_t notbefore = x509_time_to_time_t(&cert->valid_from);
  time_t notafter = x509_time_to_time_t(&cert->valid_to);

  lua_pushboolean(L, ((notbefore <= tt) && (tt <= notafter)));
  return 1;
}

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----"

/**
 * Convert the certificate to PEM format.
 */
static int meth_pem(lua_State* L)
{
  unsigned char *output_buf = (unsigned char *)malloc(2048);
  size_t len = 0;
  int res;

  memset(output_buf, 0, 2048);

  x509_crt* cert = lsec_checkx509(L, 1);
  
  if ((res = pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT, cert->raw.p, cert->raw.len, output_buf, 2048, &len)) != 0) {

    if (res == POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL) {
      free(output_buf);
      len = len + (len / 64); // https://github.com/polarssl/polarssl/issues/83
      output_buf = (unsigned char *)malloc(len);

      memset(output_buf, 0, len);
      
      if ((res = pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT, cert->raw.p, cert->raw.len, output_buf, len, &len)) != 0) {
        lua_pushnil(L);
      } else {
        lua_pushstring(L, (const char *)output_buf);
      }

    } else {
      lua_pushnil(L);
    }

  } else {
    lua_pushstring(L, (const char *)output_buf);
  }

  free(output_buf);

  return 1;
}

/**
 * Return the serial number.
 */
static int meth_serial(lua_State *L)
{
  x509_crt *cert = lsec_checkx509(L, 1);
  char buffer[1024];

  if (x509_serial_gets(buffer, 1024, &cert->serial) >= 0) {
    lua_pushstring(L, buffer);
  } else {
    lua_pushnil(L);
  }


  return 1;
}

/**
 * Return not before date.
 */
static int meth_notbefore(lua_State *L)
{
  x509_crt* cert = lsec_checkx509(L, 1);
  x509_time* valid_from = &cert->valid_from;
  
  lua_pushnumber(L, x509_time_to_time_t(valid_from));
  return 1;
}

/**
 * Return not after date.
 */
static int meth_notafter(lua_State *L)
{
  x509_crt* cert = lsec_checkx509(L, 1);
  x509_time* valid_to = &cert->valid_to;
  
  lua_pushnumber(L, x509_time_to_time_t(valid_to));
  return 1;
}

/**
 * Collect X509 objects.
 */
static int meth_destroy(lua_State* L)
{
  return 0;
}

static int meth_tostring(lua_State *L)
{
  x509_crt* cert = lsec_checkx509(L, 1);
  lua_pushfstring(L, "X509 certificate: %p", cert);
  return 1;
}

/*---------------------------------------------------------------------------*/

static int load_cert(lua_State* L)
{
  x509_crt *cert = (x509_crt *)malloc(sizeof(x509_crt));
  size_t bytes;
  const char* data;
  data = luaL_checklstring(L, 1, &bytes);

  x509_crt_init(cert);

  if (x509_crt_parse(cert, (const unsigned char *)data, bytes))
    lsec_pushx509(L, cert);
  else
    lua_pushnil(L);
  return 1;
}

/*---------------------------------------------------------------------------*/

/**
 * Certificate methods.
 */
static luaL_Reg methods[] = {
  {"extensions", meth_extensions},
  {"issuer",     meth_issuer},
  {"notbefore",  meth_notbefore},
  {"notafter",   meth_notafter},
  {"pem",        meth_pem},
  {"serial",     meth_serial},
  {"subject",    meth_subject},
  {"validat",    meth_valid_at},
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
