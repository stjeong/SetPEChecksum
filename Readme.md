What is it?
================================

Command-line tool for setting checksum value into PE Header 


How to use
================================

If it suits your convenience, just add next settings in your Visual Studio Project / Build Events / Post-build event command line


```
...[path]...\SetPEChecksum.exe /s "$(TargetPath)"
```

Or just run it.


Change Log
================================

1.0.0.0 - Oct 1, 2017

* Initial checked-in (For Koreans, read [this article](http://www.sysnet.pe.kr/2/0/11323))