# Makefile to compile xmlparser on Linux, using Mono

MCS_REFERENCES = -r:packages/MySql.Data.6.8.3/lib/net45/MySql.Data.dll -r:System.Data -r:System.Configuration
MCS_FLAGS = -optimize


all: bin/Program.exe bin/Program.exe.config

bin:
	mkdir -p bin

bin/Program.exe: bin xmlparser/Program.cs xmlparser/NanoXMLParser.cs
	mcs $(MCS_REFERENCES) $(MCS_FLAGS) -out:$@ xmlparser/Program.cs xmlparser/NanoXMLParser.cs

bin/Program.exe.config: xmlparser/App.config
	cp $< $@

clean:
	rm -rf bin/
