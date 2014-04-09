/*--------------------------------------------------------------------------
 * LuaSec 0.5
 *
 * Copyright (C) 2014 Kim Alvefur, Paul Aurich, Tobias Markmann
 *                    Matthew Wild, Bruno Silvestre.
 *
 *--------------------------------------------------------------------------*/

#ifndef LSEC_X509_H
#define LSEC_X509_H

#include <lua.h>

#include "config.h"

#include <polarssl/x509_crt.h>

void lsec_pushx509(lua_State* L, const x509_crt *cert);
x509_crt* lsec_checkx509(lua_State* L, int idx);

LSEC_API int luaopen_ssl_x509(lua_State *L);

#endif
