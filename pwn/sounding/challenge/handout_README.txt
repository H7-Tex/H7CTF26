Sounding Line

You tele-operate a salvage drone inside Cistern-9 over a text console.
The station is sealed behind its trim regulator, and past the central shaft
sits a survey transponder you re-program by playing knot-marks on a sounding line.

Shipped here:
  sounding_line            the console binary served over the network
  libc.so.6                the C library the remote instance runs against
  ld-linux-x86-64.so.2     the matching loader

Connect to the instance you are given and take the station.

  ./ld-linux-x86-64.so.2 --library-path . ./sounding_line   (to run it locally)
