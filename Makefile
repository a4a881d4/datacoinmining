CFLAG = -O3 -DTEST=0 -fPIC
LINK=$(CXX)
LMODE = dynamic
LIBS = -L/usr/lib/x86_64-linux-gnu
LIBS += \
 -Wl,-B$(LMODE) \
   -l boost_system \
   -l boost_filesystem \
   -l boost_program_options \
   -l boost_thread \
   -l ssl \
   -l crypto \
 -Wl,-Bdynamic \
   -l pthread \
   -l gmp \
 -Wl,-B$(LMODE) 

OBJS=work/prime.o work/main_poolminer.o work/util.o work/sync.o work/hash.o work/sha256_sse2_amd64.o work/sha256_xmm_amd64.o work/json_spirit_reader work/json_spirit_value work/json_spirit_writer



LIBOBJs=work/prime.o work/util.o work/hash.o

work/sha256_xmm_amd64.o:src/sha256_xmm_amd64.asm
	yasm -f elf64 -o work/sha256_xmm_amd64.o src/sha256_xmm_amd64.asm

work/sha256_sse2_amd64.o:src/sha256_sse2_amd64.cpp
	g++ -fPIC -c -o work/sha256_sse2_amd64.o src/sha256_sse2_amd64.cpp


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

work/libDM.so:$(LIBOBJs)
	$(LINK) -shared -o $@ $^ $(LIBS)

work/dms:work/main_poolminer.o work/sync.o work/json_spirit_reader work/json_spirit_value work/json_spirit_writer work/libDM.so work/libsha256.so
	$(LINK) -o $@ $^ $(LIBS)

	
all:work/dm

all-s:work/dms


clean:
	rm work/* -f


