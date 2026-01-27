# OpenMalleableC2

**Open Source Implementation of Cobalt Strike's Malleable C2**

OpenMalleableC2 is a framework-agnostic library that implements Cobalt Strike's Malleable C2 profile format for HTTP transformations. It enables security researchers and red teams to easily implement malleable C2 communications in custom tools and C2 frameworks.

It allows wholesale usage of Malleable C2 profiles to send arbitrary data over HTTP, in a transparent, (hopefully) stable way.

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
<img width="2331" height="1865" alt="image" src="https://github.com/user-attachments/assets/4b6d8c84-3d9b-4090-a8f3-e1c8ff5896e8" />


## References

- [Cobalt Strike Malleable C2 Documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm)
- [Malleable C2 Profiles Repository](https://github.com/cobalt-strike/Malleable-C2-Profiles)
- Chet Jeepiti

