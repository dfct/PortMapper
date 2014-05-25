portmapper
==========

Intercept and remap TCP or UDP traffic over ports of your choosing. 


Output from /?:

```
Port Mapper - Intercept & remap TCP or UDP traffic over ports of your choosing.

Version: 0.0.1

   /remap [tcp:#:# | udp:#:#]  [/debug]

      /remap [tcp:#:# | udp:#:#]    Specifies which TCP/UDP ports to remap. You
                                    may provide more than one set to remap.
                                    Format is protocol:currentport:newport

      /debug                        Print all packets before/after modification


Examples:
      portmapper.exe /remap tcp:80:8080
      portmapper.exe /remap udp:5000:6767 tcp:25:443 tcp:500:125 /debug
```

	  
The binary was compiled with Visual Studio 2013, so you'll need the [Visual C++ 2013 redistributables](http://www.microsoft.com/en-us/download/details.aspx?id=40784) installed to run them as is. Of course, you can also compile source.cpp with the compiler of your choice as well.

I wrote this as I couldn't reach some key ports to use SMB and a few other services due to ISP port filtering. I remapped traffic from ports 137, 138, 139, and 500 over ports that weren't filtered and did the same in reverse with Endpoint Mapping on sever side. You can read a little bit more on this at https://blog.internals.io.

Big thanks to the WinDivert project for making this possible! Their awesome library does all the heavy lifting :)
