CFLAG = -O3 -DTEST=0
LINK=$(CXX)
LMODE = dynamic
LIBS = -L/usr/lib/x86_64-linux-gnu
LIBS += \
 -Wl,-B$(LMODE) \
   -l boost_system \
   -l boost_filesystem \
   -l boost_program_options \
   -l boost_thread \
   -l boost_chrono \
   -l ssl \
   -l crypto \
 -Wl,-Bdynamic \
   -l gmp \
   -l pthread \
 -Wl,-B$(LMODE)

OBJS=work/prime.o work/main_poolminer.o work/util.o work/sync.o work/hash.o work/json_spirit_reader work/json_spirit_value work/json_spirit_writer

work/prime.o:src/prime.cpp
	$(CXX) $(CFLAG) -c -o $@ $^
work/main_poolminer.o:src/main_poolminer.cpp
	$(CXX) $(CFLAG) -c -o $@ $^
work/util.o:src/util.cpp
	$(CXX) $(CFLAG) -c -o $@ $^
work/sync.o:src/sync.cpp
	$(CXX) $(CFLAG) -c -o $@ $^
work/hash.o:src/hash.cpp
	$(CXX) $(CFLAG) -c -o $@ $^
work/json_spirit_reader:src/json/json_spirit_reader.cpp
	$(CXX) $(CFLAG) -c -o $@ $^
work/json_spirit_value:src/json/json_spirit_value.cpp
	$(CXX) $(CFLAG) -c -o $@ $^
work/json_spirit_writer:src/json/json_spirit_writer.cpp
	$(CXX) $(CFLAG) -c -o $@ $^

work/dm:$(OBJS)
	$(LINK) -o $@ $^ $(LIBS)
 
all:work/dm

clean:
	rm work/* -f


