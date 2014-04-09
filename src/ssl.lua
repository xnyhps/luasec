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

context = { setcipher = function () return true end }

function newcontext(cfg)
  local ctx = {}
  for k, v in pairs(cfg) do
    ctx[k] = v
  end
  if cfg.protocol == "sslv23" then
    ctx.minprotocol = "sslv3"
    ctx.maxprotocol = "tlsv1_2"
  else
    ctx.minprotocol = cfg.protocol
    ctx.maxprotocol = cfg.protocol
  end
  return ctx
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
   local ctx = newcontext(cfg)
   local s, msg = core.create(sock:getfd(), ctx)
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
  info.cipher, info.encryption, info.bits, info.mac, info.key, info.authentication, info.protocol = core.info(ssl)
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

