# T-409-TSAM 2019

Projects and other stuff from __T-409-TSAM__ - Computer Networks and the fundamentals of developing networked applications.

_Reykjavik University 2019._

__Students:__

Aegir Tomasson (aegir15)

Dagur Kristjansson (dagur17)

## Project 2 Usage

To compile run:<br>
```./cx```

The localhost IP is dynamically added with "```hostname -I | cut -d " " -f 1```" as the _first_ argument and the "skel.ru.is" IP is hard coded as the _second_ argument.

You only have to add the __low port__ and __high port__ and it will ba added as the _third_ and _fourth_ argument to the scanner program.

To execute run:<br>
```./run [Low port] [High port]```

To execute with output to debug.txt:<br>
```./run_debug [Low port] [High port]```