NDASSCAN - L Benfield, 2005-2014

http://www.benf.org/other/rapsody

Interesting note: (well, interesting to me)

NDASSCAN originally operated by using private signing functions in the XIMETA binaries, so versions of NDASSCAN
prior to 2.0 required XIMETA binaries with known entry points (direct call to binary offset).

Since IOCELL has open sourced the NDAS code now, we can see exactly what it is we were calling, and simply include
this code, rather than require known binaries are installed.

Note - I've only included the bare minimum here - if you intend to build this from source, you'll have to sort out your
own pcap libraries, projects etc (my visual studio project included).

I'll get round to porting this to linux RealSoonNow (honest), but I may have to find my N35 first!