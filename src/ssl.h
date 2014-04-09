#ifndef LSEC_SSL_H
#define LSEC_SSL_H

/*--------------------------------------------------------------------------
 * LuaSec 0.5
 * Copyright (C) 2006-2014 Bruno Silvestre
 *
 *--------------------------------------------------------------------------*/

#include <lua.h>

#include <luasocket/io.h>
#include <luasocket/buffer.h>
#include <luasocket/timeout.h>
#include <luasocket/socket.h>

#include <polarssl/ssl.h>
#include <polarssl/entropy.h>

#include "config.h"
// #include "context.h"

#define LSEC_STATE_NEW       1
#define LSEC_STATE_CONNECTED 2
#define LSEC_STATE_CLOSED    3

#define LSEC_IO_SSL          -100

typedef struct t_ssl_ {
  t_socket sock;
  t_io io;
  t_buffer buf;
  t_timeout tm;
  ssl_context ssl;
  ssl_session ssn;
  pk_context pk;
  x509_crt crt;
  x509_crt ca_crt;
  int state;
  int error;
  ctr_drbg_context ctr_drbg;
} t_ssl;
typedef t_ssl* p_ssl;

LSEC_API int luaopen_ssl_core(lua_State *L);

#endif
