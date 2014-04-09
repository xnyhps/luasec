/*--------------------------------------------------------------------------
 * LuaSec 0.5
 *
 * Copyright (C) 2014 Kim Alvefur, Paul Aurich, Tobias Markmann, 
 *                    Matthew Wild.
 * Copyright (C) 2006-2014 Bruno Silvestre.
 *
 *--------------------------------------------------------------------------*/

#include <errno.h>
#include <string.h>

#if defined(WIN32)
#include <Winsock2.h>
#endif

#include <lua.h>
#include <lauxlib.h>

#include <luasocket/io.h>
#include <luasocket/buffer.h>
#include <luasocket/timeout.h>
#include <luasocket/socket.h>

#include <stdlib.h>

#include <polarssl/net.h>
#include <polarssl/entropy.h>
#include <polarssl/error.h>
#include <polarssl/ctr_drbg.h>

static void *g_EntropyKey;

#include "x509.h"
#include "ssl.h"

/**
 * Underline socket error.
 */
static int lsec_socket_error()
{
#if defined(WIN32)
  return WSAGetLastError();
#else
  return errno;
#endif
}

/**
 * Map error code into string.
 */
static const char *ssl_ioerror(void *ctx, int err)
{
  p_ssl ssl = (p_ssl)ctx;
  if (err == LSEC_IO_SSL) {
    static char buffer[1024];
    
    polarssl_strerror(ssl->error, buffer, 1024);

    return buffer;
  }
  return socket_strerror(err);
}

/**
 * Close the connection before the GC collect the object.
 */
static int meth_destroy(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  if (ssl->state == LSEC_STATE_CONNECTED) {
    socket_setblocking(&ssl->sock);
    ssl_close_notify(&ssl->ssl);
  }
  if (ssl->sock != SOCKET_INVALID) {
    socket_destroy(&ssl->sock);
  }
  ssl->state = LSEC_STATE_CLOSED;
  ssl_free(&ssl->ssl);
  pk_free(&ssl->pk);
  x509_crt_free(&ssl->crt);
  return 0;
}

/**
 * Perform the TLS/SSL handshake
 */
static int handshake(p_ssl ssl)
{
  int err;
  p_timeout tm = timeout_markstart(&ssl->tm);
  if (ssl->state == LSEC_STATE_CLOSED)
    return IO_CLOSED;
  for ( ; ; ) {
    err = ssl_handshake_step(&ssl->ssl);

    switch (err) {
      case 0:
        break;
      case POLARSSL_ERR_NET_WANT_READ:
        err = socket_waitfd(&ssl->sock, WAITFD_R, tm);
        if (err == IO_TIMEOUT) return LSEC_IO_SSL;
        if (err != IO_DONE)    return err;
        break;
      case POLARSSL_ERR_NET_WANT_WRITE:
        err = socket_waitfd(&ssl->sock, WAITFD_W, tm);
        if (err == IO_TIMEOUT) return LSEC_IO_SSL;
        if (err != IO_DONE)    return err;
        break;
      default: {
        ssl->error = err;
        return LSEC_IO_SSL;
      }
    }

    if (ssl->ssl.state == SSL_HANDSHAKE_OVER) {
      ssl->state = LSEC_STATE_CONNECTED;
      return IO_DONE;
    }
  }
  return IO_UNKNOWN;
}

static void my_debug( void *ctx, int level, const char *str )
{
  fprintf( (FILE *) ctx, "%s", str );
  fflush(  (FILE *) ctx  );
}

/**
 * Send data
 */
static int ssl_send(void *ctx, const char *data, size_t count, size_t *sent,
   p_timeout tm)
{
  int err;
  p_ssl ssl = (p_ssl)ctx;
  if (ssl->state != LSEC_STATE_CONNECTED)
    return IO_CLOSED;
  *sent = 0;
  for ( ; ; ) {
    ssl->error = 0;
    err = ssl_write(&ssl->ssl, (const unsigned char*)data, (int)count);

    if (err < 0) {
      ssl->error = err;
    }

    switch (ssl->error) {
      case 0:
        *sent = err;
        return IO_DONE;
      case POLARSSL_ERR_NET_WANT_READ:
        err = socket_waitfd(&ssl->sock, WAITFD_R, tm);
        if (err == IO_TIMEOUT) return LSEC_IO_SSL;
        if (err != IO_DONE)    return err;
        break;
      case POLARSSL_ERR_NET_WANT_WRITE:
        err = socket_waitfd(&ssl->sock, WAITFD_W, tm);
        if (err == IO_TIMEOUT) return LSEC_IO_SSL;
        if (err != IO_DONE)    return err;
        break;
      case POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY:
        return IO_CLOSED;
      default: {
        ssl->error = err;
        return LSEC_IO_SSL;
      }
    }
  }
  return IO_UNKNOWN;
}

/**
 * Receive data
 */
static int ssl_recv(void *ctx, char *data, size_t count, size_t *got,
  p_timeout tm)
{
  int err;
  p_ssl ssl = (p_ssl)ctx;
  if (ssl->state != LSEC_STATE_CONNECTED)
    return IO_CLOSED;
  *got = 0;
  for ( ; ; ) {
    ssl->error = 0;
    err = ssl_read(&ssl->ssl, (unsigned char*)data, (int)count);

    if (err < 0) {
      ssl->error = err;
    }

    switch (ssl->error) {
      case 0:
        *got = err;
        return IO_DONE;
      case POLARSSL_ERR_NET_WANT_READ:
        err = socket_waitfd(&ssl->sock, WAITFD_R, tm);
        if (err == IO_TIMEOUT) return LSEC_IO_SSL;
        if (err != IO_DONE)    return err;
        break;
      case POLARSSL_ERR_NET_WANT_WRITE:
        err = socket_waitfd(&ssl->sock, WAITFD_W, tm);
        if (err == IO_TIMEOUT) return LSEC_IO_SSL;
        if (err != IO_DONE)    return err;
        break;
      case POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY:
        return IO_CLOSED;
      default: {
        ssl->error = err;
        return LSEC_IO_SSL;
      }
    }
  }
  return IO_UNKNOWN;
}

/**
 * Create a new TLS/SSL object and mark it as new.
 */
static int meth_create(lua_State *L)
{
  p_ssl ssl;
  int fd = luaL_checkint(L, 1);
  int mode = SSL_IS_CLIENT;
  int res;

  ssl = (p_ssl)lua_newuserdata(L, sizeof(t_ssl));
  if (!ssl) {
    lua_pushnil(L);
    lua_pushstring(L, "error creating SSL object");
    return 2;
  }

  luaL_getmetatable(L, "SSL:Connection");
  lua_setmetatable(L, -2);

  ssl_init(&ssl->ssl);
  pk_init(&ssl->pk);
  x509_crt_init(&ssl->crt);

  lua_pushvalue(L, 2);
  lua_pushnil(L);
  
  while (lua_next(L, -2)) {
    lua_pushvalue(L, -2);
    const char *key = lua_tostring(L, -1);
    const char *value = lua_tostring(L, -2);

    if (strcmp(key, "key") == 0) {
      if ((res = pk_parse_keyfile(&ssl->pk, value, NULL)) != 0) {
        lua_pop(L, 3);
        lua_pushnil(L);

        char buffer[1024];

        polarssl_strerror(res, buffer, 1024);

        lua_pushfstring(L, "error reading private key: %s", buffer);
        return 2;
      }
    } else if (strcmp(key, "certificate") == 0) {
      if ((res = x509_crt_parse_file(&ssl->crt, value)) != 0) {
        lua_pop(L, 3);
        lua_pushnil(L);

        char buffer[1024];

        polarssl_strerror(res, buffer, 1024);

        lua_pushfstring(L, "error reading certificate: %s", buffer);
        return 2;
      }
    } else if (strcmp(key, "mode") == 0) {
      if (strcmp(value, "client") == 0) {
        mode = SSL_IS_CLIENT;
      } else if (strcmp(value, "server") == 0) {
        mode = SSL_IS_SERVER;
      } else {
        lua_pushnil(L);
        lua_pushstring(L, "invalid mode, must be client or server");
        return 2;
      }
    }
    printf("%s => %s\n", key, value);
    lua_pop(L, 2);
  }

  lua_pop(L, 1);

  ssl->state = LSEC_STATE_NEW;
  ssl->sock = fd;
  
  socket_setnonblocking(&ssl->sock);
  
  ssl_set_own_cert(&ssl->ssl, &ssl->crt, &ssl->pk);
  ssl_set_endpoint(&ssl->ssl, mode);
  ssl_set_authmode(&ssl->ssl, SSL_VERIFY_NONE);
  ssl_set_bio(&ssl->ssl, net_recv, &ssl->sock, net_send, &ssl->sock);
  // ssl_set_dbg(&ssl->ssl, my_debug, stdout);

  entropy_context *entropy;

  lua_rawgeti(L, LUA_REGISTRYINDEX, (int)&g_EntropyKey);
  entropy = lua_touserdata(L, -1);

  lua_pop(L, 1);
  if (!entropy) {
    entropy = lua_newuserdata(L, sizeof(entropy_context));
    lua_rawseti(L, LUA_REGISTRYINDEX, (int)&g_EntropyKey);
    entropy_init(entropy);
  }

  if (ctr_drbg_init(&ssl->ctr_drbg, entropy_func, entropy, NULL, 0)) {
    lua_pushnil(L);
    lua_pushfstring(L, "error creating RNG object");
    return 2;
  }

  ssl_set_rng(&ssl->ssl, ctr_drbg_random, &ssl->ctr_drbg);
  // ssl_set_session(&ssl->ssl, &ssl->ssn);

  io_init(&ssl->io, (p_send)ssl_send, (p_recv)ssl_recv, 
    (p_error) ssl_ioerror, ssl);
  timeout_init(&ssl->tm, -1, -1);
  buffer_init(&ssl->buf, &ssl->io, &ssl->tm);

  return 1;
}

/**
 * Buffer send function
 */
static int meth_send(lua_State *L) {
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  return buffer_meth_send(L, &ssl->buf);
}

/**
 * Buffer receive function
 */
static int meth_receive(lua_State *L) {
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  return buffer_meth_receive(L, &ssl->buf);
}

/**
 * Get the buffer's statistics.
 */
static int meth_getstats(lua_State *L) {
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  return buffer_meth_getstats(L, &ssl->buf);
}

/**
 * Set the buffer's statistics.
 */
static int meth_setstats(lua_State *L) {
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  return buffer_meth_setstats(L, &ssl->buf);
}

/**
 * Select support methods
 */
static int meth_getfd(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  lua_pushnumber(L, ssl->sock);
  return 1;
}

/**
 * Lua handshake function.
 */
static int meth_handshake(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  int err = handshake(ssl);
  if (err == IO_DONE) {
    lua_pushboolean(L, 1);
    return 1;
  }
  lua_pushboolean(L, 0);
  lua_pushstring(L, ssl_ioerror((void*)ssl, err));
  return 2;
}

/**
 * Close the connection.
 */
static int meth_close(lua_State *L)
{
  meth_destroy(L);
  return 0;
}

/**
 * Set timeout.
 */
static int meth_settimeout(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  return timeout_meth_settimeout(L, &ssl->tm);
}

/**
 * Check if there is data in the buffer.
 */
// static int meth_dirty(lua_State *L)
// {
//   int res = 0;
//   p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
//   if (ssl->state != LSEC_STATE_CLOSED)
//     res = !buffer_isempty(&ssl->buf) || SSL_pending(ssl->ssl);
//   lua_pushboolean(L, res);
//   return 1;
// }

/**
 * Return the state information about the SSL object.
 */
// static int meth_want(lua_State *L)
// {
//   p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
//   int code = (ssl->state == LSEC_STATE_CLOSED)
//              ? SSL_NOTHING
//              : SSL_want(ssl->ssl);
//   switch(code) {
//   case SSL_NOTHING: lua_pushstring(L, "nothing"); break;
//   case SSL_READING: lua_pushstring(L, "read"); break;
//   case SSL_WRITING: lua_pushstring(L, "write"); break;
//   case SSL_X509_LOOKUP: lua_pushstring(L, "x509lookup"); break;
//   }
//   return 1;
// }
  
/**
 * Return the compression method used.
 */
static int meth_compression(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  int compression = ssl->ssl.session->compression;

  if (compression == SSL_COMPRESS_NULL) {
    lua_pushstring(L, "NULL");
  } else {
    lua_pushstring(L, "Deflate");
  }

  return 1;
}

/**
 * Return the nth certificate of the peer's chain.
 */
static int meth_getpeercertificate(lua_State *L)
{
  int n;
  const x509_crt *cert;
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  if (ssl->state != LSEC_STATE_CONNECTED) {
    lua_pushnil(L);
    lua_pushstring(L, "closed");
    return 2;
  }
  /* Default to the first cert */
  n = luaL_optint(L, 2, 1);
  /* This function is 1-based, but OpenSSL is 0-based */
  if (n < 0) {
    lua_pushnil(L);
    lua_pushliteral(L, "invalid certificate index");
    return 2;
  }
  cert = ssl_get_peer_cert(&ssl->ssl);
  while (n > 1) {
    n--;
    cert = cert ? cert->next : NULL;
  }
  if (cert)
    lsec_pushx509(L, cert);
  else
    lua_pushnil(L);
  return 1;
}

/**
 * Return the chain of certificate of the peer.
 */
static int meth_getpeerchain(lua_State *L)
{
  int n = 0;
  const x509_crt *cert;
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  if (ssl->state != LSEC_STATE_CONNECTED) {
    lua_pushnil(L);
    lua_pushstring(L, "closed");
    return 2;
  }
  cert = ssl_get_peer_cert(&ssl->ssl);
  while (cert) {
    n++;
    lsec_pushx509(L, cert);
    cert = cert->next;
  }
  return n;
}

/**
 * Copy the table src to the table dst.
 */
static void copy_error_table(lua_State *L, int src, int dst)
{
  lua_pushnil(L); 
  while (lua_next(L, src) != 0) {
    if (lua_istable(L, -1)) {
      /* Replace the table with its copy */
      lua_newtable(L);
      copy_error_table(L, dst+2, dst+3);
      lua_remove(L, dst+2);
    }
    lua_pushvalue(L, -2);
    lua_pushvalue(L, -2);
    lua_rawset(L, dst);
    /* Remove the value and leave the key */
    lua_pop(L, 1);
  }
}

/**
 * Return the verification state of the peer chain.
 */
// static int meth_getpeerverification(lua_State *L)
// {
//   long err;
//   p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
//   if (ssl->state != LSEC_STATE_CONNECTED) {
//     lua_pushboolean(L, 0);
//     lua_pushstring(L, "closed");
//     return 2;
//   }
//   err = SSL_get_verify_result(ssl->ssl);
//   if (err == X509_V_OK) {
//     lua_pushboolean(L, 1);
//     return 1;
//   }
//   luaL_getmetatable(L, "SSL:Verify:Registry");
//   lua_pushlightuserdata(L, (void*)ssl->ssl);
//   lua_gettable(L, -2);
//   if (lua_isnil(L, -1))
//     lua_pushstring(L, X509_verify_cert_error_string(err));
//   else {
//     /* Copy the table of errors to avoid modifications */
//     lua_newtable(L);
//     copy_error_table(L, lua_gettop(L)-1, lua_gettop(L));
//   }
//   lua_pushboolean(L, 0);
//   lua_pushvalue(L, -2);
//   return 2;
// }

/**
 * Get the latest "Finished" message sent out.
 */
// static int meth_getfinished(lua_State *L)
// {
//   size_t len = 0;
//   char *buffer = NULL;
//   p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
//   if (ssl->state != LSEC_STATE_CONNECTED) {
//     lua_pushnil(L);
//     lua_pushstring(L, "closed");
//     return 2;
//   }
//   if ((len = SSL_get_finished(ssl->ssl, NULL, 0)) == 0)
//     return 0;
//   buffer = (char*)malloc(len);
//   if (!buffer) {
//     lua_pushnil(L);
//     lua_pushstring(L, "out of memory");
//     return 2;
//   }
//   SSL_get_finished(ssl->ssl, buffer, len);
//   lua_pushlstring(L, buffer, len);
//   free(buffer);
//   return 1;
// }

/**
 * Gets the latest "Finished" message received.
 */
// static int meth_getpeerfinished(lua_State *L)
// {
//   size_t len = 0;
//   char *buffer = NULL;
//   p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
//   if (ssl->state != LSEC_STATE_CONNECTED) {
//     lua_pushnil(L);
//     lua_pushstring(L, "closed");
//     return 0;
//   }
//   if ((len = SSL_get_peer_finished(ssl->ssl, NULL, 0)) == 0)
//     return 0;
//   buffer = (char*)malloc(len);
//   if (!buffer) {
//     lua_pushnil(L);
//     lua_pushstring(L, "out of memory");
//     return 2;
//   }
//   SSL_get_peer_finished(ssl->ssl, buffer, len);
//   lua_pushlstring(L, buffer, len);
//   free(buffer);
//   return 1;
// }

/**
 * Object information -- tostring metamethod
 */
static int meth_tostring(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  lua_pushfstring(L, "SSL connection: %p%s", ssl,
    ssl->state == LSEC_STATE_CLOSED ? " (closed)" : "");
  return 1;
}

/**
 * Add a method in the SSL metatable.
 */
static int meth_setmethod(lua_State *L)
{
  luaL_getmetatable(L, "SSL:Connection");
  lua_pushstring(L, "__index");
  lua_gettable(L, -2);
  lua_pushvalue(L, 1);
  lua_pushvalue(L, 2);
  lua_settable(L, -3);
  return 0;
}

static const char *key_exchange_name(key_exchange_type_t key_exchange)
{
  switch (key_exchange) {
    case POLARSSL_KEY_EXCHANGE_NONE: return "None";
    case POLARSSL_KEY_EXCHANGE_RSA: return "RSA";
    case POLARSSL_KEY_EXCHANGE_DHE_RSA: return "DHE";
    case POLARSSL_KEY_EXCHANGE_ECDHE_RSA: return "ECDHE";
    case POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA: return "ECDHE";
    case POLARSSL_KEY_EXCHANGE_PSK: return "PSK";
    case POLARSSL_KEY_EXCHANGE_DHE_PSK: return "DHE";
    case POLARSSL_KEY_EXCHANGE_RSA_PSK: return "RSA";
    case POLARSSL_KEY_EXCHANGE_ECDHE_PSK: return "ECDHE";
    case POLARSSL_KEY_EXCHANGE_ECDH_RSA: return "ECDH";
    case POLARSSL_KEY_EXCHANGE_ECDH_ECDSA: return "ECDH";
    default: return "???";
  }
}

static const char *auth_name(key_exchange_type_t key_exchange)
{
  switch (key_exchange) {
    case POLARSSL_KEY_EXCHANGE_NONE: return "None";
    case POLARSSL_KEY_EXCHANGE_RSA: return "RSA";
    case POLARSSL_KEY_EXCHANGE_DHE_RSA: return "RSA";
    case POLARSSL_KEY_EXCHANGE_ECDHE_RSA: return "RSA";
    case POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA: return "ECDSA";
    case POLARSSL_KEY_EXCHANGE_PSK: return "PSK";
    case POLARSSL_KEY_EXCHANGE_DHE_PSK: return "PSK";
    case POLARSSL_KEY_EXCHANGE_RSA_PSK: return "PSK";
    case POLARSSL_KEY_EXCHANGE_ECDHE_PSK: return "PSK";
    case POLARSSL_KEY_EXCHANGE_ECDH_RSA: return "RSA";
    case POLARSSL_KEY_EXCHANGE_ECDH_ECDSA: return "ECDSA";
    default: return "???";
  }
}

/**
 * Return information about the connection.
 */
static int meth_info(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  int cipher_id = ssl->ssl.session->ciphersuite;
  const ssl_ciphersuite_t *ciphersuite = ssl_ciphersuite_from_id(cipher_id);
  const cipher_info_t *cipher_info = cipher_info_from_type(ciphersuite->cipher);
  const md_info_t *md_info = md_info_from_type(ciphersuite->mac);

  lua_pushstring(L, ciphersuite->name);
  lua_pushstring(L, cipher_info->name);
  lua_pushnumber(L, cipher_info->key_length);
  lua_pushstring(L, md_info->name);
  lua_pushstring(L, key_exchange_name(ciphersuite->key_exchange));
  lua_pushstring(L, auth_name(ciphersuite->key_exchange));
  return 6;
}

static int meth_copyright(lua_State *L)
{
  lua_pushstring(L, "LuaSec 0.5 - Copyright (C) 2006-2011 Bruno Silvestre"
#if defined(WITH_LUASOCKET)
                    "\nLuaSocket 3.0-RC1 - Copyright (C) 2004-2013 Diego Nehab"
#endif
  );
  return 1;
}

/*---------------------------------------------------------------------------*/

/**
 * SSL methods 
 */
static luaL_Reg methods[] = {
  {"close",               meth_close},
  {"getfd",               meth_getfd},
  // {"getfinished",         meth_getfinished},
  {"getpeercertificate",  meth_getpeercertificate},
  {"getpeerchain",        meth_getpeerchain},
  // {"getpeerverification", meth_getpeerverification},
  // {"getpeerfinished",     meth_getpeerfinished},
  {"getstats",            meth_getstats},
  {"setstats",            meth_setstats},
  // {"dirty",               meth_dirty},
  {"dohandshake",         meth_handshake},
  {"receive",             meth_receive},
  {"send",                meth_send},
  {"settimeout",          meth_settimeout},
  // {"want",                meth_want},
  {NULL,                  NULL}
};

/**
 * SSL metamethods.
 */
static luaL_Reg meta[] = {
  {"__gc",       meth_destroy},
  {"__tostring", meth_tostring},
  {NULL, NULL}
};

/**
 * SSL functions. 
 */
static luaL_Reg funcs[] = {
  {"compression", meth_compression},
  {"create",      meth_create},
  {"info",        meth_info},
  // {"setfd",       meth_setfd},
  {"setmethod",   meth_setmethod},
  {"copyright",   meth_copyright},
  {NULL,          NULL}
};

/**
 * Initialize modules.
 */
#if (LUA_VERSION_NUM == 501)
LSEC_API int luaopen_ssl_core(lua_State *L)
{
#if defined(WITH_LUASOCKET)
  /* Initialize internal library */
  socket_open();
#endif
   
  /* Register the functions and tables */
  luaL_newmetatable(L, "SSL:Connection");
  luaL_register(L, NULL, meta);

  lua_newtable(L);
  luaL_register(L, NULL, methods);
  lua_setfield(L, -2, "__index");

  luaL_register(L, "ssl.core", funcs);
  lua_pushnumber(L, SOCKET_INVALID);
  lua_setfield(L, -2, "invalidfd");

  return 1;
}
#else
LSEC_API int luaopen_ssl_core(lua_State *L)
{

#if defined(WITH_LUASOCKET)
  /* Initialize internal library */
  socket_open();
#endif

  /* Register the functions and tables */
  luaL_newmetatable(L, "SSL:Connection");
  luaL_setfuncs(L, meta, 0);

  lua_newtable(L);
  luaL_setfuncs(L, methods, 0);
  lua_setfield(L, -2, "__index");

  lua_newtable(L);
  luaL_setfuncs(L, funcs, 0);
  lua_pushnumber(L, SOCKET_INVALID);
  lua_setfield(L, -2, "invalidfd");

  return 1;
}
#endif
