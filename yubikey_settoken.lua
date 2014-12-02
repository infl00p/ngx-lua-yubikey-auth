-- display a login page, check username and yubikey and set session cookie based


-- initial variables
local sslid=ngx.var.ssl_session_id or ""
local yubikey_apikey=ngx.var.yubiapikey
local yubikey_apiid=ngx.var.yubiapiid
local serversecret=ngx.var.serversecret
local cookietimeout=tonumber(ngx.var.cookietimeout)
local cookiedomain=ngx.var.basedomain or ngx.var.server_name


if ngx.var.SITEDEBUG then ngx.log(ngx.STDERR, "session_id=", ngx.var.ssl_session_id, " sslid=", sslid) end

-- templates
local bodytemplate = [[
<html>
<head><title>OTP Gateway Authentication</title></head><body>
<h1>OTP login</h1>
<h2>You are connecting from ip %s</h2>
<p>Please enter your otp credentials</p>
<form method="post">
<ul >
<li>
<label>Name </label>
<div>
<input name="name" type="text" maxlength="32" value=""/> 
</div> 
</li>
<li>
<label>OTP </label>
<div>
<input name="otp" type="text" maxlength="255" value=""/> 
</div> 
</li>
<li>
<input type="submit" name="submit"/>
</li>
</ul>
</form> 
</body></html>]]


local function checkcreds()
    ngx.req.read_body()
    local postargs, err = ngx.req.get_post_args(2)
    
    if not postargs or postargs["name"] == nil or postargs["otp"] == nil or postargs["otp"]:len() < 32 or postargs["otp"]:len() >48 then
        if ngx.var.SITEDEBUG then ngx.log(ngx.STDERR, 'No credentials or invalid data, displaying login page') end
        return("login")
    end

    local username=postargs["name"]
    local yubikeyhash=postargs["otp"]

    -- TODO - check yubiformat (only printable characters)
    if string.find(yubikeyhash, "%c") or string.find(username, "%W") then
        return("login")
    end

    -- Build the authentication request pass to server
    local seed=string.byte(yubikeyhash,math.random(17,#yubikeyhash))
    math.randomseed(seed+ngx.time())
    local yubinonce=string.format("%x",math.random(10^15,10^16))

    local result=ngx.location.capture("/yubiauth", {args={id = 1, otp = yubikeyhash, nonce = yubinonce }})

    if result.body:find("status=OK") then
        ngx.log(ngx.STDERR, 'Yubikey server authentication success for user '..username.." otp:"..yubikeyhash.." ssl_id:"..sslid)

        -- build cookie
        local expirationtime=ngx.time()+cookietimeout
        local securehash=ngx.encode_base64(ngx.hmac_sha1(ngx.hmac_sha1(serversecret, username..expirationtime), username..expirationtime..sslid))
        local cookiedata="token="..ngx.encode_base64(username..":"..tostring(expirationtime)..":"..securehash)

        -- set cookie
        ngx.header["Set-Cookie"] = cookiedata.."; Path=/; Expires="..ngx.cookie_time(expirationtime-1).."; Secure; HttpOnly"

        -- redirect to base url
        if ngx.var.SITEDEBUG then ngx.log(ngx.STDERR, 'redirecting client to base url') end
        ngx.redirect("/")
        
    else
        ngx.log(ngx.STDERR, 'Yubikey server authentication fail')
        
        return("login")
    end
    
end

local function printloginpage()
    local html = string.format(bodytemplate, ngx.var.remote_addr)
    ngx.header.content_type = "text/html"
    ngx.print(html)
end


if checkcreds() == "login" then
    printloginpage()
end
