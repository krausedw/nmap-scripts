local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
  Detect likely vulnerable Ivanti Connect Secure and Ivanti Policy Secure versions.
]]

---
-- @usage
-- nmap --script http-vuln-ivanti-ics-ips.nse <target>
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-vuln-ivanti-ics-ips:
-- |   VULNERABLE:
-- |   Numerous Ivanti Connect Secure and Ivanti Policy Secure Vulnerabilities
-- |     State: LIKELY VULNERABLE
-- |     Risk factor: High
-- |     Check results:
-- |       8.3.7.65025
-- |     Extra information:
-- |       Older Ivanti version (8.3.7.65025)
-- |     References:
-- |_      https://www.ivanti.com/blog/topics/security-advisory

author = "David Krause"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local function search_match(body)
  stdnse.print_debug("%s: search_match()", SCRIPT_NAME)
  local hash = nil

  if (body ~= nil) then
    stdnse.print_debug("%s: search_match() Trying to find a hash", SCRIPT_NAME)
    hash = string.match(body, '/dana%-na/css/ds_(%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x)%.css')
    if (hash == nil) then
      stdnse.print_debug("%s: search_match() Trying to find an older hash", SCRIPT_NAME)
      hash = string.match(body, '/dana%-na/css/ds%.css%?(%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x)"')
    end
    if (hash == nil) then
      stdnse.print_debug("%s: search_match() Trying to find gina version", SCRIPT_NAME)
      hash = string.match(body, 'ProductVersion" VALUE="(%d+%.%d+%.%d+%.%d+)">')
    end
    if (hash == nil) then
      stdnse.print_debug("%s: search_match() Trying to find Ivanti without hash", SCRIPT_NAME)
      hash = string.match(body, '/dana%-na/css/ds%.css')
    end
  end

  return hash
end

local function lookup_vuln(hash)
  stdnse.print_debug("%s: lookup_vuln()", SCRIPT_NAME)
  local vuln = {
    title = "Numerous Ivanti Connect Secure and Ivanti Policy Secure Vulnerabilities",
    references = "https://www.ivanti.com/blog/topics/security-advisory",
    risk_factor = "High",
    check_results = hash,
    extra_info = nil,
    state = vulns.STATE.VULN
  }

  -- This function needs to be updated each time there is a new Ivanti release.
  -- You have to find someone running each particular release and then look at the HTML for the hash.
  -- The hashes below should be most of the ones for the latest patched version, but there may be others.
  -- You can search on Shodan or other tools for these:
  -- shodan = "https://www.shodan.io/search?query=http.html%3A"..hash

  stdnse.print_debug("%s: lookup_vuln() Trying to lookup hash", SCRIPT_NAME)
  if (hash == "/dana-na/css/ds.css") then
    vuln.extra_info = "Older unknown Ivanti version"
    vuln.state = vulns.STATE.LIKELY_VULN
  elseif (hash == "7fa107638cd936f310c90e911f49e8521eb1d9adf56adc28c2d977de20101206") then
    vuln.extra_info = "Latest Ivanti version released Feb 8, 2024 ("..hash..")"
    vuln.state = vulns.STATE.NOT_VULN
  elseif (hash == "3a5b32b4832655b2b4589911f51e83f58ce122f96b78fb38f3e4eba1cb9c491e") then
    vuln.extra_info = "Latest Ivanti version released Feb 8, 2024 ("..hash..")"
    vuln.state = vulns.STATE.NOT_VULN
  elseif (hash == "07b3e7195e98a4b7a1a862c215a6c2dc8869e758c55880ff9122512c66998d21") then
    vuln.extra_info = "Latest Ivanti version released Feb 8, 2024 ("..hash..")"
    vuln.state = vulns.STATE.NOT_VULN
  elseif (hash == "3b3e7e2d8655eeb05f8cdaf666db494daee601c2ac9193552db10a8eb609de13") then
    vuln.extra_info = "Latest Ivanti version released Feb 8, 2024 ("..hash..")"
    vuln.state = vulns.STATE.NOT_VULN
  elseif (hash == "5d9534b7fc89601b15ad0dd9c603e930fbc5ecfacea931048131d51fa959bb79") then
    vuln.extra_info = "Latest Ivanti version released Feb 8, 2024 ("..hash..")"
    vuln.state = vulns.STATE.NOT_VULN
  elseif (hash == "6e3361fa1cc0f4267c7f4cee3757fe1ee13c50dec396d2c3cb872a7ff7c89c69") then
    vuln.extra_info = "Latest Ivanti version released Feb 8, 2024 ("..hash..")"
    vuln.state = vulns.STATE.NOT_VULN
  elseif (hash == "314ead76519e271becfd954adce01514c5726431e74c2449654d97bb9f2f56e1") then
    vuln.extra_info = "Latest Ivanti version released Feb 8, 2024 ("..hash..")"
    vuln.state = vulns.STATE.NOT_VULN
  elseif (hash == "b426cedf0d9ff7c81bf6818cca211a4179f330db3f884754c7f83dd73f778678") then
    vuln.extra_info = "Latest Ivanti version released Feb 8, 2024 ("..hash..")"
    vuln.state = vulns.STATE.NOT_VULN
  elseif (hash == "9554a6e812bd6b80acda8d60307b0c20e0b54a06419cc848ed28db63bb0ad7fd") then
    vuln.extra_info = "Latest Ivanti version released Feb 8, 2024 ("..hash..")"
    vuln.state = vulns.STATE.NOT_VULN
  elseif (hash == "6e1c5a723b6402359835d9c06de9d0220881eed738003b0469211c38c1b474de") then
    vuln.extra_info = "Latest Ivanti version released Feb 8, 2024 ("..hash..")"
    vuln.state = vulns.STATE.NOT_VULN
  elseif (hash ~= nil) and string.match(hash, '%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x') then
    vuln.extra_info = "Unknown Ivanti version ("..hash..")"
    vuln.state = vulns.STATE.LIKELY_VULN
  elseif (hash ~= nil) then
    vuln.extra_info = "Older Ivanti version ("..hash..")"
    vuln.state = vulns.STATE.LIKELY_VULN
  else
    vuln.state = vulns.STATE.NOT_VULN
  end

  return vuln
end

action = function(host, port)
  local css = "/dana-na/css/ds.css"
  local gina = "/dana-na/nc/nc_gina_ver.txt"
  local notfound = "/404"
  local welcome = "/dana-na/auth/welcome.cgi"
  local welcomedefault = "/dana-na/auth/url_default/welcome.cgi"
  local options = {header={}} options['header']['User-Agent'] = "Mozilla/5.0 (compatible; Pulsesecure)"

  stdnse.print_debug("%s: action() Trying 404", SCRIPT_NAME)
  local response = http.get(host, port, notfound, options)
  local hash = search_match(response.body)

  if (hash == nil or hash == css) then
    stdnse.print_debug("%s: action() Trying /", SCRIPT_NAME)
    response = http.get(host, port, "/", options)
    hash = search_match(response.body)
  end
  if (hash == nil or hash == css) then
    stdnse.print_debug("%s: action() Trying welcome", SCRIPT_NAME)
    response = http.get(host, port, welcome, options)
    hash = search_match(response.body)
  end
  if (hash == nil or hash == css) then
    stdnse.print_debug("%s: action() Trying welcomedefault", SCRIPT_NAME)
    response = http.get(host, port, welcomedefault, options)
    hash = search_match(response.body)
  end
  if (hash == nil or hash == css) then
    stdnse.print_debug("%s: action() Trying gina", SCRIPT_NAME)
    response = http.get(host, port, gina, options)
    hash = search_match(response.body)
  end

  if (hash == nil) then
    stdnse.print_debug("%s: action() Could not find a version hash", SCRIPT_NAME)
  else
    stdnse.print_debug("%s: action() Found a version hash", SCRIPT_NAME)
  end

  local vuln = lookup_vuln(hash) 
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  return report:make_output(vuln)
end
