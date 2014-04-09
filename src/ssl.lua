------------------------------------------------------------------------------
-- LuaSec 0.5
-- Copyright (C) 2006-2014 Bruno Silvestre
--
------------------------------------------------------------------------------

local core    = require("ssl.core")
-- local context = require("ssl.context")
local x509    = require("ssl.x509")

module("ssl", package.seeall)

_VERSION   = "0.5.PR"
_COPYRIGHT = core.copyright()

-- Export
loadcertificate = x509.load

-- We must prevent the contexts to be collected before the connections,
-- otherwise the C registry will be cleared.
local registry = setmetatable({}, {__mode="k"})

function newcontext(cfg)
  return cfg
end

--
--
--
local function optexec(func, param, ctx)
  if param then
    if type(param) == "table" then
      return func(ctx, unpack(param))
    else
      return func(ctx, param)
    end
  end
  return true
end

--
--
--
function wrap(sock, cfg)
   local s, msg = core.create(sock:getfd(), cfg)
   if s then
      sock:setfd(core.invalidfd)
      registry[s] = ctx
      return s
   end
   return nil, msg 
end

--
-- Extract connection information.
--
local function info(ssl, field)
  local str, comp, err, protocol
  comp, err = core.compression(ssl)
  if err then
    return comp, err
  end
  -- Avoid parser
  if field == "compression" then
    return comp
  end
  local info = {compression = comp}
  info.cipher, info.encryption, info.bits, info.mac, info.key, info.authentication = core.info(ssl)
  info.algbits = info.bits
  info.export = false
  if field then
    return info[field]
  end
  -- Empty?
  return ( (next(info)) and info )
end

--
-- Set method for SSL connections.
--
core.setmethod("info", info)

