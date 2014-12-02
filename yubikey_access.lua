-- access script for yubikey auth
-- matches the token stored in a cookie to the internally stored session id

local sslid = ngx.var.ssl_session_id or ""
local serversecret = ngx.var.serversecret

if ngx.var.SITEDEBUG then ngx.log(ngx.STDERR, "session_id=", ngx.var.ssl_session_id, " sslid=", sslid) end

if ngx.var.cookie_token ~= nil then
    local token = ngx.decode_base64(ngx.var.cookie_token);
    if ngx.var.SITEDEBUG then ngx.log(ngx.STDERR, 'Token exists') end
    -- get cookie contents
    local _,count = string.gsub(token, ":", "")
    if count == 2 then
        if ngx.var.SITEDEBUG then ngx.log(ngx.STDERR, 'Token is right length') end
        local pos1=token:find(":")
        local pos2=token:find(":",pos1+1)
        local username=token:sub(0,pos1-1) or ""
        local token_expiration=token:sub(pos1+1,pos2-1) or ""
        local securehash=token:sub(pos2+1)

        -- check if token is valid and recent
        local rebuilthash=ngx.encode_base64(ngx.hmac_sha1(ngx.hmac_sha1(serversecret, username..token_expiration), username..token_expiration..sslid))
        if securehash==rebuilthash and tonumber(token_expiration)>ngx.time() then
            if ngx.var.SITEDEBUG then ngx.log(ngx.STDERR, 'Token is valid and recent, passing') end
            return
        end
    end

    -- delete invalid token
    if ngx.var.SITEDEBUG then ngx.log(ngx.STDERR, 'Deleting invalid token') end
    ngx.header["Set-Cookie"] = "token=deleted; path=/; Expires=Thu, 01-Jan-1970 00:00:01 GMT"

end

if ngx.var.SITEDEBUG then ngx.log(ngx.STDERR, 'Token does not exist') end
ngx.redirect("/otpauth/")
