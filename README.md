# OpenMalleableC2

**Open Source Implementation of Cobalt Strike's Malleable C2**

OpenMalleableC2 is a framework-agnostic library that implements Cobalt Strike's Malleable C2 profile format for HTTP transformations. It enables security researchers and red teams to easily implement malleable C2 communications in custom tools and C2 frameworks.

It allows wholesale usage of Malleable C2 profiles to send arbitrary data over HTTP, in a transparent, stable (hopefully) way.

## Why did I make this?
There are many open source C2 frameworks that have varying degrees of HTTP traffic customization features.  However, even the more developed frameworks such as Mythic, Havoc, Adaptix etc. still lack the depth of HTTP traffic customization that Cobalt Strike's Malleable C2 allows, in terms of embedding callback data within convincingly innocent looking HTTP requests. The goal of this project is to allow open source tooling to both benefit from the customization depth of the Malleable C2 system as well as the existing resources dependent on it (e.g. profiles, profile generator tools etc.)

Its mostly working, but I make no guarantees about its stability at this time. Do report bugs if found :)


## Quick Start

The provided example is a simple "ping pong" agent and server that demonstrates the typical Beacon callback. The agent will send back a GET callback to check-in for taskings, then send a POST callback to post task output back to the server.

In this example, the taskings are just a placeholder random string, that the agent will retrieve, reverse and post back as the result. The server verifies that the reversed string is correct, and sends a response accordingly.


**Run ping-pong example:**
```
# Start server
python examples\pingpong_server.py profiles\gmail.profile

# Run agent (in another terminal)
.\examples\pingpong_agent.exe profiles\gmail.profile
```

Example output:
pingpong_server.py:
```
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:8080
Press CTRL+C to quit

[DEBUG] GET request received!
[DEBUG] Raw HTTP request:
GET /_/scs/mail-static/_/js/? HTTP/1.1
Connection: Keep-Alive
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.5
Cookie: OSID=QkVBQ09OLUNIRUNLSU46IENvbXB1dGVyPURFU0tUT1AtSzVJRVY0RiBVc2VyPUFkbWluIFBJRD0zODc2OCBPUz1XaW5kb3dzIEFyY2g9eDY0IFRpbWVzdGFtcD0xNzY5NTA1NjYw    
User-Agent: Mozilla/5.0
Dnt: 1
Host: 127.0.0.1:8080


============================================================
[Server] Received GET /_/scs/mail-static/_/js/
============================================================
[Server] Extracted metadata (102 bytes):
[Server] BEACON-CHECKIN: Computer=DESKTOP-K5IEV4F User=Admin PID=38768 OS=Windows Arch=x64 Timestamp=1769505660
[Server] Generated challenge: DjjYXnXcLSpwGPzJqcdUfOsIlEy7sO0k
[Server] Sending task (32 bytes):
[Server] "DjjYXnXcLSpwGPzJqcdUfOsIlEy7sO0k"
[DEBUG] Raw HTTP response:
HTTP/1.1 200 OK
Content-Length: 832
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Cache-Control: public, max-age=31536000
X-XSS-Protection: 1; mode=block
Server: GSE
Alternate-Protocol: 443:quic,p=1

try()catch(e)(_DumpException(e))N(L.Oa(),"sy558");P(L.Oa(),"sy558");O(L.Oa(),"sy558");try()catch(e)(_DumpException(e))N(L.Oa(),"sy580");P(L.Oa(),"sy580");O(L.Oa(),"sy580")try(DjjYXnXcLSpwGPzJqcdUfOsIlEy7sO0kvar f2=function(a)(a=a.wa;return"application/chromium-bookmark-folder"==a||"application/chromium-root-folder"==a||"application/vnd.google-apps.folder"==a||"application/vnd.google-apps.photoalbum"==a||"application/vnd.google-apps.rollupphotoalbum"==a),g2=function(a)(return a.ra),s8d=function(a)(return a?hb(a,function(a)(return new UP(a)):[]),h2=function(a)(switch(a)(case "all":case "docs-images":case "docs-images-and-videos":case "docs-videos":case "documents":case "drawings":case "folders":case "forms":case "pdfs":case "presentations":case "sites":case "spreadsheets":case "tables":return!0)return!1); O(L.Oa(),"sy588")
127.0.0.1 - - [27/Jan/2026 17:21:00] "GET /_/scs/mail-static/_/js/ HTTP/1.1" 200 -

[DEBUG] POST request received!
[DEBUG] Raw HTTP request:
POST /mail/u/0/?ui=d3244c4707&hop=6928632&start=0 HTTP/1.1
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded;charset=utf-8
Cookie: OSID=MTQ4MzA=
User-Agent: Mozilla/5.0
Content-Length: 80
Host: 127.0.0.1:8080

VEFTSy1SRVNVTFQ6IFJldmVyc2VkT3V0cHV0PWswT3M3eUVsSXNPZlVkY3FKelBHd3BTTGNYblhZampE

============================================================
[Server] Received POST /mail/u/0/
============================================================
[Server] Extracted session ID (5 bytes):
[Server] 14830
[Server] Extracted task output (60 bytes):
[Server] TASK-RESULT: ReversedOutput=k0Os7yElIsOfUdcqJzPGwpSLcXnXYjjD
[Server] Original challenge: DjjYXnXcLSpwGPzJqcdUfOsIlEy7sO0k
[Server] Expected reversed:  k0Os7yElIsOfUdcqJzPGwpSLcXnXYjjD
[Server] SUCCESS! Verified reversed challenge in output
[Server] Sending confirmation (74 bytes)
[DEBUG] Raw HTTP response:
HTTP/1.1 200 OK
Content-Length: 176
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
X-XSS-Protection: 1; mode=block
Server: GSE

W1tbImFwbSIsIkNPTkZJUk1FRDogVGFzayBjb21wbGV0ZWQgc3VjY2Vzc2Z1bGx5ISBSZWNlaXZlZCByZXZlcnNlZCBzdHJpbmcgY29ycmVjdGx5Il0sWyJjaSIsW11dLFsiY20iLFtdLFtdXV0sJ2RiYjg3OTZhODBkNDVlMWYnXQ==
127.0.0.1 - - [27/Jan/2026 17:21:00] "POST /mail/u/0/?ui=d3244c4707&hop=6928632&start=0 HTTP/1.1" 200 -
```
  
pingpong_agent.exe
```
============================================================
Ping Pong PoC Agent
============================================================
[Agent] Reading profile file: ..\profiles\gmail.profile
[Agent] Parsing profile from memory...
[Agent] Profile loaded: unnamed
[Agent] User-Agent: (none)

[Agent] ===== GET: Requesting tasks from server =====
[Agent] Metadata (102 bytes): "BEACON-CHECKIN: Computer=DESKTOP-K5IEV4F User=Admin PID=38768 OS=Windows Arch=x64 Timestamp=1769505660"
[Agent] Received task (32 bytes): "DjjYXnXcLSpwGPzJqcdUfOsIlEy7sO0k"
[Agent] Task string: "DjjYXnXcLSpwGPzJqcdUfOsIlEy7sO0k"
[Agent] Reversed task: "k0Os7yElIsOfUdcqJzPGwpSLcXnXYjjD"

[Agent] ===== POST: Sending task results to server =====
[Agent] Session ID (5 bytes): "14830"
[Agent] Task output (60 bytes): "TASK-RESULT: ReversedOutput=k0Os7yElIsOfUdcqJzPGwpSLcXnXYjjD"
[Agent] Server confirmation (74 bytes): "CONFIRMED: Task completed successfully! Received reversed string correctly"

[Agent] ===== Ping pong complete =====
[Agent] Successfully executed server task and reported results!
```

## References

- [Cobalt Strike Malleable C2 Documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm)
- [Malleable C2 Profiles Repository](https://github.com/cobalt-strike/Malleable-C2-Profiles)
- Chet Jeepiti

