//===
// by xolokram/TB
// 2013
//===

#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <map>

#include "uint256.h"
#include "sync.h"
#include "Block.h"
#include "prime.h"
#include "serialize.h"
#include "sha256sse.h"

#include "json/json_spirit_value.h"
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/uuid/sha1.hpp>

#define VERSION_MAJOR 0
#define VERSION_MINOR 9
#define VERSION_EXT "RC1"

#define MAX_THREADS 32

// <START> be compatible to original code (not actually used!)
void StartShutdown() {
  exit(0);
}
// </END>

/*********************************
* global variables, structs and extern functions
*********************************/

extern CBlockIndex *pindexBest;
extern void BitcoinMiner( CBlockProvider *CBlockProvider,
                          unsigned int thread_id );
extern bool fPrintToConsole;
extern bool fDebug;

struct blockHeader_t {
  // comments: BYTES <index> + <length>
  int           nVersion;            // 0+4
  uint256       hashPrevBlock;       // 4+32
  uint256       hashMerkleRoot;      // 36+32
  unsigned int  nTime;               // 68+4
  unsigned int  nBits;               // 72+4
  unsigned int  nNonce;              // 76+4
  unsigned char primemultiplier[48]; // 80+48
};                                   // =128 bytes header (80 default + 48 primemultiplier)

size_t thread_num_max;
static size_t fee_to_pay;
static size_t miner_id;
static boost::asio::ip::tcp::socket* socket_to_server;
static boost::posix_time::ptime t_start;
static std::map<int,unsigned long> statistics;
static bool running;
static volatile int submitting_share;
std::string pool_username;
std::string pool_password;

/*********************************
* helping functions
*********************************/

void convertDataToBlock(unsigned char* blockData, CBlock& block) {
  {
    std::stringstream ss;
    for (int i = 7; i >= 0; --i)
		ss << std::setw(8) << std::setfill('0') << std::hex << *((int *)(blockData + 4) + i);
    ss.flush();
    block.hashPrevBlock.SetHex(ss.str().c_str());
  }
  {
    std::stringstream ss;
    for (int i = 7; i >= 0; --i)
		ss << std::setw(8) << std::setfill('0') << std::hex << *((int *)(blockData + 36) + i);
    ss.flush();
    block.hashMerkleRoot.SetHex(ss.str().c_str());
  }
  block.nVersion               = *((int *)(blockData));
  block.nTime                  = *((unsigned int *)(blockData + 68));
  block.nBits                  = *((unsigned int *)(blockData + 72));
  block.nNonce                 = *((unsigned int *)(blockData + 76));
  block.bnPrimeChainMultiplier = 0;
}

/*********************************
* class CBlockProviderGW to (incl. SUBMIT_BLOCK)
*********************************/

class CBlockProviderGW : public CBlockProvider {
public:

	CBlockProviderGW() : CBlockProvider(), nTime_offset(0), _blocks(NULL) {}

	virtual ~CBlockProviderGW() { /* TODO */ }
	
	virtual unsigned int GetAdjustedTimeWithOffset(unsigned int thread_id) {
		return nTime_offset + ((((unsigned int)GetAdjustedTime() + thread_num_max) / thread_num_max) * thread_num_max) + thread_id;
	}
	
	virtual CBlock* getOriginalBlock() {
		return _blocks;
	}

	virtual CBlock* getBlock(unsigned int thread_id, unsigned int last_time, unsigned int counter) {
		boost::unique_lock<boost::shared_mutex> lock(_mutex_getwork);
		if (_blocks == NULL) return NULL;
		CBlock* block = NULL;
		block = new CBlock(_blocks->GetBlockHeader());
		unsigned int new_time = GetAdjustedTimeWithOffset(thread_id);
		//if (new_time == last_time)
		//	new_time += thread_num_max;
		new_time += counter * thread_num_max;
		block->nTime = new_time; //TODO: check if this is the same time like before!?
		//std::cout << "[WORKER" << thread_id << "] got_work block=" << block->GetHash().ToString().c_str() << std::endl;
		return block;
	}

	void setBlocksFromData(unsigned char* data) {
		CBlock* blocks = new CBlock(); //[thread_num_count];
		//for (size_t i = 0; i < thread_num_count; ++i)
		//	convertDataToBlock(data+i*128,blocks[i]);
		convertDataToBlock(data,*blocks);
		//
		unsigned int nTime_local = GetAdjustedTime();
		unsigned int nTime_server = blocks->nTime;
		nTime_offset = nTime_local > nTime_server ? 0 : (nTime_server-nTime_local);		
		//
		CBlock* old_blocks = NULL;
		{
			boost::unique_lock<boost::shared_mutex> lock(_mutex_getwork);
			old_blocks = _blocks;
			_blocks = blocks;
		}
		if (old_blocks != NULL) delete old_blocks;
	}

	void submitBlock(CBlock *block) {
		blockHeader_t blockraw;
		blockraw.nVersion       = block->nVersion;
		blockraw.hashPrevBlock  = block->hashPrevBlock;
		blockraw.hashMerkleRoot = block->hashMerkleRoot;
		blockraw.nTime          = block->nTime;
		blockraw.nBits          = block->nBits;
		blockraw.nNonce         = block->nNonce;

		//std::cout << "submit: " << block->hashMerkleRoot.ToString().c_str() << std::endl;

		std::vector<unsigned char> primemultiplier = block->bnPrimeChainMultiplier.getvch();
		if (primemultiplier.size() > 47) {
			std::cerr << "[WORKER] share submission warning: not enough space for primemultiplier" << std::endl;
			return;
		}
		blockraw.primemultiplier[0] = primemultiplier.size();
		for (size_t i = 0; i < primemultiplier.size(); ++i)
			blockraw.primemultiplier[1 + i] = primemultiplier[i];

		boost::posix_time::ptime submit_start = boost::posix_time::second_clock::universal_time();
		boost::system::error_code submit_error = boost::asio::error::host_not_found; //run at least 1 time
		++submitting_share;
		while (submit_error && running && (boost::posix_time::second_clock::universal_time() - submit_start).total_seconds() < 80) {
			while (socket_to_server == NULL && running && (boost::posix_time::second_clock::universal_time() - submit_start).total_seconds() < 80) //socket error was issued somewhere else
				boost::this_thread::sleep(boost::posix_time::milliseconds(100));
			if (running && (boost::posix_time::second_clock::universal_time() - submit_start).total_seconds() < 80) {
				boost::asio::write(*socket_to_server, boost::asio::buffer((unsigned char*)&blockraw, 128), boost::asio::transfer_at_least(1), submit_error); //FaF
				//size_t len = boost::asio::write(*socket_to_server, boost::asio::buffer((unsigned char*)&blockraw, 128), boost::asio::transfer_all(), submit_error);
				//socket_to_server->write_some(boost::asio::buffer((unsigned char*)&blockraw, 128), submit_error);
				//if (submit_error)
				//	std::cout << submit_error << " @ write_submit" << std::endl;
			}
		}
		--submitting_share;
	}

	void forceReconnect() {
		std::cout << "force reconnect if possible!" << std::endl;
		if (socket_to_server != NULL) {
			boost::system::error_code close_error;
			socket_to_server->close(close_error);
			//if (close_error)
			//	std::cout << close_error << " @ close" << std::endl;
		}
	}

protected:
	unsigned int nTime_offset;
	boost::shared_mutex _mutex_getwork;
	CBlock* _blocks;
};

/*********************************
* multi-threading
*********************************/

class CMasterThreadStub {
public:
  virtual void wait_for_master() = 0;
  virtual boost::shared_mutex& get_working_lock() = 0;
};

class CWorkerThread { // worker=miner
public:

	CWorkerThread(CMasterThreadStub *master, unsigned int id, CBlockProviderGW *bprovider)
		: _working_lock(NULL), _id(id), _master(master), _bprovider(bprovider), _thread(&CWorkerThread::run, this) { }

	void run() {
		std::cout << "[WORKER" << _id << "] Hello, World!" << std::endl;
		_master->wait_for_master();
		std::cout << "[WORKER" << _id << "] GoGoGo!" << std::endl;
		boost::this_thread::sleep(boost::posix_time::seconds(2));
		BitcoinMiner(_bprovider, _id);
		std::cout << "[WORKER" << _id << "] Bye Bye!" << std::endl;
	}

	void work() { // called from within master thread
		_working_lock = new boost::shared_lock<boost::shared_mutex>(_master->get_working_lock());
	}

protected:
  boost::shared_lock<boost::shared_mutex> *_working_lock;
  unsigned int _id;
  CMasterThreadStub *_master;
  CBlockProviderGW  *_bprovider;
  boost::thread _thread;
};

class CMasterThread : public CMasterThreadStub {
public:

  CMasterThread(CBlockProviderGW *bprovider) : CMasterThreadStub(), _bprovider(bprovider) {}

  void run() {

	{
		boost::unique_lock<boost::shared_mutex> lock(_mutex_master);
		std::cout << "spawning " << thread_num_max << " worker thread(s)" << std::endl;

		for (unsigned int i = 0; i < thread_num_max; ++i) {
			CWorkerThread *worker = new CWorkerThread(this, i, _bprovider);
			worker->work();
		}
	}

    boost::asio::io_service io_service;
    boost::asio::ip::tcp::resolver resolver(io_service); //resolve dns
    boost::asio::ip::tcp::resolver::query query(GetArg("-poolip", "127.0.0.1"), GetArg("-poolport", "1337"));
    boost::asio::ip::tcp::resolver::iterator endpoint;
	boost::asio::ip::tcp::resolver::iterator end;
	boost::asio::ip::tcp::no_delay nd_option(true);
	boost::asio::socket_base::keep_alive ka_option(true);

	while (running) {
		endpoint = resolver.resolve(query);
		boost::scoped_ptr<boost::asio::ip::tcp::socket> socket;
		boost::system::error_code error_socket = boost::asio::error::host_not_found;
		while (error_socket && endpoint != end)
		{
		  //socket->close();
		  socket.reset(new boost::asio::ip::tcp::socket(io_service));
		  boost::asio::ip::tcp::endpoint tcp_ep = *endpoint++;
		  socket->connect(tcp_ep, error_socket);
		  std::cout << "connecting to " << tcp_ep << std::endl;
		}
		socket->set_option(nd_option);
		socket->set_option(ka_option);

		if (error_socket) {
			std::cout << error_socket << std::endl;
			boost::this_thread::sleep(boost::posix_time::seconds(10));
			continue;
		}

		{ //send hello message
			char* hello = new char[pool_username.length()+/*v0.2/0.3=*/2+/*v0.4=*/20+/*v0.7=*/1+pool_password.length()];
			memcpy(hello+1, pool_username.c_str(), pool_username.length());
			*((unsigned char*)hello) = pool_username.length();
			*((unsigned char*)(hello+pool_username.length()+1)) = 0; //hi, i'm v0.4+
			*((unsigned char*)(hello+pool_username.length()+2)) = VERSION_MAJOR;
			*((unsigned char*)(hello+pool_username.length()+3)) = VERSION_MINOR;
			*((unsigned char*)(hello+pool_username.length()+4)) = thread_num_max;
			*((unsigned char*)(hello+pool_username.length()+5)) = fee_to_pay;
			*((unsigned short*)(hello+pool_username.length()+6)) = miner_id;
			*((unsigned int*)(hello+pool_username.length()+8)) = nSieveExtensions;
			*((unsigned int*)(hello+pool_username.length()+12)) = nSievePercentage;
			*((unsigned int*)(hello+pool_username.length()+16)) = nSieveSize;
			*((unsigned char*)(hello+pool_username.length()+20)) = pool_password.length();
			memcpy(hello+pool_username.length()+21, pool_password.c_str(), pool_password.length());
			*((unsigned short*)(hello+pool_username.length()+21+pool_password.length())) = 0; //EXTENSIONS
			boost::system::error_code error;
			socket->write_some(boost::asio::buffer(hello, pool_username.length()+2+20+1+pool_password.length()), error);
			int i;
			printf("Hello message: ");
			for( i=0;i<pool_username.length()+2+20+1+pool_password.length();i++ ) 
				printf("%02x(%c) ",hello[i],hello[i]);
			printf("\n");
			
			if (error)
				std::cout << error << " @ write_some_hello" << std::endl;
			delete[] hello;
		}

		socket_to_server = socket.get(); 

		int reject_counter = 0;
		bool done = false;
		while (!done) {
			int type = -1;
			{ 
				unsigned char buf = 0; //get header
				boost::system::error_code error;
				size_t len = boost::asio::read(*socket_to_server, boost::asio::buffer(&buf, 1), boost::asio::transfer_all(), error);
				if (error == boost::asio::error::eof)
					break; // Connection closed cleanly by peer.
				else if (error) {
					break;
				}
				type = buf;
				if (len != 1)
					std::cout << "error on read1: " << len << " should be " << 1 << std::endl;
			}

			switch (type) {
				case 0: {
					size_t buf_size = 128; //*thread_num_max;
					unsigned char* buf = new unsigned char[buf_size]; //get header
					boost::system::error_code error;
					size_t len = boost::asio::read(*socket_to_server, boost::asio::buffer(buf, buf_size), boost::asio::transfer_all(), error);
					if (error == boost::asio::error::eof) {
						done = true;
						break; // Connection closed cleanly by peer.
					} else if (error) {
						done = true;
						break;
					}
					if (len == buf_size) {
						_bprovider->setBlocksFromData(buf);
						std::cout << "[MASTER] work received" << std::endl;
					} else
						std::cout << "error on read2a: " << len << " should be " << buf_size << std::endl;
					delete[] buf;

					CBlockIndex *pindexOld = pindexBest;
					pindexBest = new CBlockIndex();
					delete pindexOld;

				} break;
				case 1: {
					size_t buf_size = 4;
					int buf; //get header
					boost::system::error_code error;
					size_t len = boost::asio::read(*socket_to_server, boost::asio::buffer(&buf, buf_size), boost::asio::transfer_all(), error);
					if (error == boost::asio::error::eof) {
						done = true;
						break; // Connection closed cleanly by peer.
					} else if (error) {
						done = true;
						break;
					}
					if (len == buf_size) {
						int retval = buf > 100000 ? 1 : buf;
						std::cout << "[MASTER] submitted share -> " <<
							(retval == 0 ? "REJECTED" : retval < 0 ? "STALE" : retval ==
							1 ? "BLOCK" : "SHARE") << std::endl;
						std::map<int,unsigned long>::iterator it = statistics.find(retval);
						if (retval > 0)
							reject_counter = 0;
						else
							reject_counter++;
						if (reject_counter >= 3) {
							std::cout << "too many rejects (3) in a row, forcing reconnect." << std::endl;
							socket->close();
							done = true;
						}
						if (it == statistics.end())
							statistics.insert(std::pair<int,unsigned long>(retval,1));
						else
							statistics[retval]++;
						stats_running();
					} else
						std::cout << "error on read2b: " << len << " should be " << buf_size << std::endl;
				} break;
				case 2: 
					break;
				default:
					break;
			}
		}

		socket_to_server = NULL; //TODO: lock/mutex
		for (int i = 0; i < 50 && submitting_share < 1; ++i) //wait <5 seconds until reconnect (force reconnect when share is waiting to be submitted)
			boost::this_thread::sleep(boost::posix_time::milliseconds(100));
	}
  }

  ~CMasterThread() {}

  void wait_for_master() {
    boost::shared_lock<boost::shared_mutex> lock(_mutex_master);
  }

  boost::shared_mutex& get_working_lock() {
    return _mutex_working;
  }

private:

  void wait_for_workers() {
    boost::unique_lock<boost::shared_mutex> lock(_mutex_working);
  }

  CBlockProviderGW  *_bprovider;

  boost::shared_mutex _mutex_master;
  boost::shared_mutex _mutex_working;

	// Provides real time stats
	void stats_running() {
		if (!running) return;
		std::cout << std::fixed;
		std::cout << std::setprecision(1);
		boost::posix_time::ptime t_end = boost::posix_time::second_clock::universal_time();
		unsigned long rejects = 0;
		unsigned long stale = 0;
		unsigned long valid = 0;
		unsigned long blocks = 0;
		for (std::map<int,unsigned long>::iterator it = statistics.begin(); it != statistics.end(); ++it) {
			if (it->first < 0) stale += it->second;
			if (it->first == 0) rejects = it->second;
			if (it->first == 1) blocks = it->second;
			if (it->first > 1) valid += it->second;
		}
		std::cout << "[STATS] " << DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTimeMillis() / 1000).c_str() << " | ";
		for (std::map<int,unsigned long>::iterator it = statistics.begin(); it != statistics.end(); ++it)
			if (it->first > 1)
				std::cout << it->first << "-CH: " << it->second << " (" <<
				  ((valid+blocks > 0) ? (static_cast<double>(it->second) / static_cast<double>(valid+blocks)) * 100.0 : 0.0) << "% | " <<
				  ((valid+blocks > 0) ? (static_cast<double>(it->second) / (static_cast<double>((t_end - t_start).total_seconds()) / 3600.0)) : 0.0) << "/h), ";
		if (valid+blocks+rejects+stale > 0) {
		std::cout << "VL: " << valid+blocks << " (" << (static_cast<double>(valid+blocks) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%), ";
		std::cout << "RJ: " << rejects << " (" << (static_cast<double>(rejects) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%), ";
		std::cout << "ST: " << stale << " (" << (static_cast<double>(stale) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%)" << std::endl;
		} else {
			std::cout <<  "VL: " << 0 << " (" << 0.0 << "%), ";
			std::cout <<  "RJ: " << 0 << " (" << 0.0 << "%), ";
			std::cout <<  "ST: " << 0 << " (" << 0.0 << "%)" << std::endl;
		}
	}
};

/*********************************
* exit / end / shutdown
*********************************/

void stats_on_exit() {
	if (!running) return;
	boost::this_thread::sleep(boost::posix_time::seconds(1));
	std::cout << std::fixed;
	std::cout << std::setprecision(3);
	boost::posix_time::ptime t_end = boost::posix_time::second_clock::universal_time();
	unsigned long rejects = 0;
	unsigned long stale = 0;
	unsigned long valid = 0;
	unsigned long blocks = 0;
	for (std::map<int,unsigned long>::iterator it = statistics.begin(); it != statistics.end(); ++it) {
		if (it->first < 0) stale += it->second;
		if (it->first == 0) rejects = it->second;
		if (it->first == 1) blocks = it->second;
		if (it->first > 1) valid += it->second;
	}
	std::cout << std::endl;
	std::cout << "********************************************" << std::endl;
	std::cout << "*** running time: " << static_cast<double>((t_end - t_start).total_seconds()) / 3600.0 << "h" << std::endl;
	std::cout << "***" << std::endl;
	for (std::map<int,unsigned long>::iterator it = statistics.begin(); it != statistics.end(); ++it)
		if (it->first > 1)
			std::cout << "*** " << it->first << "-chains: " << it->second << "\t(" <<
			  ((valid+blocks > 0) ? (static_cast<double>(it->second) / static_cast<double>(valid+blocks)) * 100.0 : 0.0) << "% | " <<
			  ((valid+blocks > 0) ? (static_cast<double>(it->second) / (static_cast<double>((t_end - t_start).total_seconds()) / 3600.0)) : 0.0) << "/h)" <<
			  std::endl;
	if (valid+blocks+rejects+stale > 0) {
	std::cout << "***" << std::endl;
	std::cout << "*** valid: " << valid+blocks << "\t(" << (static_cast<double>(valid+blocks) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%)" << std::endl;
	std::cout << "*** rejects: " << rejects << "\t(" << (static_cast<double>(rejects) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%)" << std::endl;
	std::cout << "*** stale: " << stale << "\t(" << (static_cast<double>(stale) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%)" << std::endl;
	} else {
		std::cout <<  "*** valid: " << 0 << "\t(" << 0.0 << "%)" << std::endl;
		std::cout <<  "*** rejects: " << 0 << "\t(" << 0.0 << "%)" << std::endl;
		std::cout <<  "*** stale: " << 0 << "\t(" << 0.0 << "%)" << std::endl;
	}
	std::cout << "********************************************" << std::endl;
	boost::this_thread::sleep(boost::posix_time::seconds(3));
}

void exit_handler() {
	//cleanup for not-retarded OS
	if (socket_to_server != NULL) {
		socket_to_server->close();
		socket_to_server = NULL;
	}
	stats_on_exit();
	running = false;
}



static sighandler_t set_signal_handler (int signum, sighandler_t signalhandler) {
   struct sigaction new_sig, old_sig;
   new_sig.sa_handler = signalhandler;
   sigemptyset (&new_sig.sa_mask);
   new_sig.sa_flags = SA_RESTART;
   if (sigaction (signum, &new_sig, &old_sig) < 0)
      return SIG_ERR;
   return old_sig.sa_handler;
}

void ctrl_handler(int signum) {
	exit(1);
}


/*********************************
* main - this is where it begins
*********************************/
int main(int argc, char **argv)
{
  std::cout << "********************************************" << std::endl;
  std::cout << "*** Xolominer - Primecoin Pool Miner v" << VERSION_MAJOR << "." << VERSION_MINOR << " " << VERSION_EXT << std::endl;
  std::cout << "*** by xolokram/TB - www.beeeeer.org - glhf" << std::endl;
  std::cout << "***" << std::endl;
  std::cout << "*** thx to Sunny King & mikaelh" << std::endl;
  std::cout << "*** press CTRL+C to exit" << std::endl;
  std::cout << "********************************************" << std::endl;

  t_start = boost::posix_time::second_clock::universal_time();
  running = true;

  set_signal_handler(SIGINT, ctrl_handler);

  if (argc < 2)
  {
    std::cerr << "usage: " << argv[0] <<
    " -poolfee=<fee-in-%> -poolip=<ip> -poolport=<port> -pooluser=<user> -poolpassword=<password>" <<
    std::endl;
    return EXIT_FAILURE;
  }

  const int atexit_res = std::atexit(exit_handler);
  if (atexit_res != 0)
    std::cerr << "atexit registration failed, shutdown will be dirty!" << std::endl;

  // init everything:
  ParseParameters(argc, argv);

  socket_to_server = NULL;
  pool_share_minimum = (unsigned int)GetArgN("-poolshare", 7);
  thread_num_max = GetArgN("-genproclimit", 1); // what about boost's hardware_concurrency() ?
  fee_to_pay = GetArgN("-poolfee", 3);
  miner_id = GetArgN("-minerid", 0);
  pool_username = GetArg("-pooluser", "");
  pool_password = GetArg("-poolpassword", "");

  if (thread_num_max == 0 || thread_num_max > MAX_THREADS)
  {
    std::cerr << "usage: " << "current maximum supported number of threads = " << MAX_THREADS << std::endl;
    return EXIT_FAILURE;
  }

  if (fee_to_pay == 0 || fee_to_pay > 100)
  {
    std::cerr << "usage: " << "please use a pool fee between [1 , 100]" << std::endl;
    return EXIT_FAILURE;
  }

  if (miner_id > 65535)
  {
    std::cerr << "usage: " << "please use a miner id between [0 , 65535]" << std::endl;
    return EXIT_FAILURE;
  }
  
  { //password to sha1
    boost::uuids::detail::sha1 sha;
    sha.process_bytes(pool_password.c_str(), pool_password.size());
    unsigned int digest[5];
    sha.get_digest(digest);
    std::stringstream ss;
    ss << std::setw(5) << std::setfill('0') << std::hex << (digest[0] ^ digest[1] ^ digest[4]) << (digest[2] ^ digest[3] ^ digest[4]);
    pool_password = ss.str();
  }
std::cout << pool_username << std::endl;

  fPrintToConsole = true; // always on
  fDebug          = GetBoolArg("-debug");

  pindexBest = new CBlockIndex();

  GeneratePrimeTable();
  std::ofstream output_file("miner_data");
  output_file.close();
  // ok, start mining:
  CBlockProviderGW* bprovider = new CBlockProviderGW();
  CMasterThread *mt = new CMasterThread(bprovider);
  mt->run();

  // end:
  return EXIT_SUCCESS;
}

double dPrimesPerSec = 0.0;
double dChainsPerMinute = 0.0;
double dChainsPerDay = 0.0;
int64 nHPSTimerStart = 0;


void BitcoinMiner( CBlockProvider *block_provider, unsigned int thread_id )
{
    printf("PrimecoinMiner started\n");
    RenameThread("primecoin-miner");

    // Each thread has its own kcd ey and counter
    unsigned int nExtraNonce = 0; //^

    unsigned int nPrimorialMultiplier = nPrimorialHashFactor;
    double dTimeExpected = 0;   // time expected to prime chain (micro-second)
    int64 nSieveGenTime = 0; // how many milliseconds sieve generation took
    bool fIncrementPrimorial = true; // increase or decrease primorial factor

    CBlock *pblock = NULL;
	CBlock *orgblock = NULL;
	uint256 old_hash;
	unsigned int old_nonce = 0;
	unsigned int blockcnt = 0;
	uint32_t nNoncePreThread = 0;
		struct work blockwork;
			
    try { loop {
       
		CBlockIndex* pindexPrev = pindexBest;

    if ((pblock = block_provider->getBlock(thread_id, pblock == NULL ? 0 : pblock->nTime, blockcnt)) == NULL) { 
	  	printf("get work failure\n");
      MilliSleep(20000);
      continue;
    } 
	  else if (old_hash == pblock->GetHeaderHash()) {
    	if (old_nonce >= 0xffff0000) {
		  	MilliSleep(100);
				if (fDebug && GetBoolArg("-printmining"))
					printf("Nothing to do --- uh ih uh ah ah bing bang!!\n");
          continue;
		  	} else
		  	  	pblock->nNonce = old_nonce;
    } 
	  else {
    	old_hash = pblock->GetHeaderHash();
			old_nonce = 0;
			nNoncePreThread = thread_id * 0x1000000;
			if (orgblock == block_provider->getOriginalBlock())
				++blockcnt;
    }


        //
        // Search
        //
        int64 nStart = GetTime();
        bool fNewBlock = true;
        unsigned int nTriedMultiplier = 0;

        // Primecoin: try to find hash divisible by primorial
        //unsigned int nHashFactor = PrimorialFast(nPrimorialHashFactor);

        uint256 phash;
        mpz_class mpzHash;
        mpz_class mpzFixedMultiplier;
        
        loop {
        	memcpy(blockwork.pdata,&(pblock->nVersion),80);
        	pblock->nNonce=nNoncePreThread;
        	blockwork.target = 3;
        	blockwork.max_nonce = pblock->nNonce+100000;
        	uint32_t new_nonce = scanhash_sse2_64( &blockwork );
        	if( new_nonce!= -1 ) {
        		pblock->nNonce=new_nonce;
        		nNoncePreThread=new_nonce+1;
        		//printf("fix[%d] mul: %lld\n",(int)thread_id,(long long int)blockwork.mulfactor);
        		mpzFixedMultiplier=blockwork.mulfactor;
        		phash = pblock->GetHeaderHash();
        		mpz_set_uint256(mpzHash.get_mpz_t(), phash);
        		break;
        	}
        	pblock->nNonce=blockwork.max_nonce;
        	nNoncePreThread=blockwork.max_nonce+1;
        }
        // Primecoin: primorial fixed multiplier
        unsigned int nRoundTests = 0;
        unsigned int nRoundPrimesHit = 0;
        int64 nPrimeTimerStart = GetTimeMicros();
        
				
        loop
        {
            unsigned int nTests = 0;
            unsigned int nPrimesHit = 0;
            unsigned int nChainsHit = 0;

            // Primecoin: adjust round primorial so that the generated prime candidates meet the minimum
            // Primecoin: mine for prime chain
            unsigned int nProbableChainLength;
            if (MineProbablePrimeChain( *pblock
            	, mpzFixedMultiplier
            	, fNewBlock
            	, nTriedMultiplier
            	, nProbableChainLength
            	, nTests
            	, nPrimesHit
            	, nChainsHit
            	, mpzHash
            	, nPrimorialMultiplier
            	, nSieveGenTime
            	, pindexPrev
            	, block_provider != NULL
            	, 0))
            {
								block_provider->submitBlock(pblock);
								old_nonce = pblock->nNonce + 1;
			
								static CCriticalSection cs;
	              {
	                LOCK(cs);

	                std::ofstream output_file("miner_data",std::ios::app);
	                /*
			                static const int CURRENT_VERSION=2;
									    int nVersion;
									    uint256 hashPrevBlock;
									    uint256 hashMerkleRoot;
									    unsigned int nTime;
									    unsigned int nBits;  // Primecoin: prime chain target, see prime.cpp
									    unsigned int nNonce;
									*/
	                output_file << "Block" << std::endl;
									output_file << pblock->nVersion << std::endl;
									output_file << pblock->hashPrevBlock.ToString().c_str() << std::endl;
									output_file << pblock->hashMerkleRoot.ToString().c_str() << std::endl;
									output_file << pblock->nTime << std::endl;
									output_file << pblock->nBits << std::endl;
	                output_file << pblock->nNonce << std::endl;
									output_file << pblock->GetHash().ToString().c_str() << std::endl;
	 								output_file << pblock->GetHeaderHash().ToString().c_str() << std::endl;
	                output_file << mpzFixedMultiplier.get_str(10) << std::endl;
	                output_file << fNewBlock << std::endl;
	                output_file << nTriedMultiplier << std::endl;
	                output_file << nPrimorialMultiplier << std::endl;
	                output_file << mpzHash.get_str(16) << std::endl;

	                output_file.close();
	              }
		
                break;
            }

            nRoundTests += nTests;
            nRoundPrimesHit += nPrimesHit;

            // Meter primes/sec
            static volatile int64 nPrimeCounter;
            static volatile int64 nTestCounter;
            static volatile int64 nChainCounter;
            static double dChainExpected;
            int64 nMillisNow = GetTimeMillis();
            if (nHPSTimerStart == 0)
            {
                nHPSTimerStart = nMillisNow;
                nPrimeCounter = 0;
                nTestCounter = 0;
                nChainCounter = 0;
                dChainExpected = 0;
            }
            else
            {
                nPrimeCounter += nPrimesHit;
                nTestCounter += nTests;
                nChainCounter += nChainsHit;
            }
            if (nMillisNow - nHPSTimerStart > 60000)
            {
                static CCriticalSection cs;
                {
                    LOCK(cs);
                    if (nMillisNow - nHPSTimerStart > 60000)
                    {
                        double dPrimesPerMinute = 60000.0 * nPrimeCounter / (nMillisNow - nHPSTimerStart);
                        dPrimesPerSec = dPrimesPerMinute / 60.0;
                        double dTestsPerSec = 1000.0 * nTestCounter / (nMillisNow - nHPSTimerStart);
                        dChainsPerMinute = 60000.0 * nChainCounter / (nMillisNow - nHPSTimerStart);
                        dChainsPerDay = 86400000.0 * dChainExpected / (GetTimeMillis() - nHPSTimerStart);
                        nHPSTimerStart = nMillisNow;
                        nPrimeCounter = 0;
                        nTestCounter = 0;
                        nChainCounter = 0;
                        dChainExpected = 0;
                        static int64 nLogTime = 0;
                        if (nMillisNow - nLogTime > 59000)
                        {
                            nLogTime = nMillisNow;
                            printf("[STATS] %s | %4.0f primes/s, %4.0f tests/s, %4.0f %d-chains/h, %3.3f chains/d\n", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nLogTime / 1000).c_str(), dPrimesPerSec, dTestsPerSec, dChainsPerMinute * 60.0, nStatsChainLength, dChainsPerDay);
                        }
                    }
                }
            }

				old_nonce = pblock->nNonce;

            // Check for stop or if block needs to be rebuilt
            boost::this_thread::interruption_point();
             if (pblock->nNonce >= 0xffff0000)
                break;
            if (pindexPrev != pindexBest/* || (block_provider != NULL && GetTime() - nStart > 200)*/)
                break;
			if (thread_id == 0 && block_provider != NULL && (GetTime() - nStart) > 300) { //5 minutes no update? something's wrong -> reconnect!
				block_provider->forceReconnect();
				nStart = GetTime();
			}
            if (fNewBlock) //aka: sieve's done, we need a updated nonce
            {
                // Primecoin: a sieve+primality round completes
                // Primecoin: estimate time to block
                const double dTimeExpectedPrev = dTimeExpected;
                unsigned int nCalcRoundTests = std::max(1u, nRoundTests);
                // Make sure the estimated time is very high if only 0 primes were found
                if (nRoundPrimesHit == 0)
                    nCalcRoundTests *= 1000;
                int64 nRoundTime = (GetTimeMicros() - nPrimeTimerStart);
                dTimeExpected = (double) nRoundTime / nCalcRoundTests;
                double dRoundChainExpected = (double) nRoundTests;
                for (unsigned int n = 0, nTargetLength = TargetGetLength(pblock->nBits); n < nTargetLength; n++)
                {
                    double dPrimeProbability = EstimateCandidatePrimeProbability(nPrimorialMultiplier, n);
                    dTimeExpected = dTimeExpected / std::max(0.01, dPrimeProbability);
                    dRoundChainExpected *= dPrimeProbability;
                }
                dChainExpected += dRoundChainExpected;
                if (fDebug && GetBoolArg("-printmining"))
                {
                    double dPrimeProbabilityBegin = EstimateCandidatePrimeProbability(nPrimorialMultiplier, 0);
                    unsigned int nTargetLength = TargetGetLength(pblock->nBits);
                    double dPrimeProbabilityEnd = EstimateCandidatePrimeProbability(nPrimorialMultiplier, nTargetLength - 1);
                    printf("PrimecoinMiner() : Round primorial=%u tests=%u primes=%u time=%uus pprob=%1.6f pprob2=%1.6f tochain=%6.3fd expect=%3.9f\n", nPrimorialMultiplier, nRoundTests, nRoundPrimesHit, (unsigned int) nRoundTime, dPrimeProbabilityBegin, dPrimeProbabilityEnd, ((dTimeExpected/1000000.0))/86400.0, dRoundChainExpected);
                }

                // Primecoin: update time and nonce
                //pblock->nTime = max(pblock->nTime, (unsigned int) GetAdjustedTime());
                pblock->nTime = std::max(pblock->nTime, block_provider->GetAdjustedTimeWithOffset(thread_id));
                pblock->nNonce++;
                loop {
        					memcpy(blockwork.pdata,&(pblock->nVersion),80);
				        	pblock->nNonce=nNoncePreThread;
				        	blockwork.target = 3;
				        	blockwork.max_nonce = pblock->nNonce+100000;
				        	uint32_t new_nonce = scanhash_sse2_64( &blockwork );
				        	if( new_nonce!= -1 ) {
				        		pblock->nNonce=new_nonce;
				        		nNoncePreThread=new_nonce+1;
				        		//printf("fix[%d] mul: %lld\n",(int)thread_id,(long long int)blockwork.mulfactor);
				        		mpzFixedMultiplier=blockwork.mulfactor;
				        		phash = pblock->GetHeaderHash();
				        		mpz_set_uint256(mpzHash.get_mpz_t(), phash);
				        		break;
				        	}
				        	pblock->nNonce=blockwork.max_nonce;
				        	nNoncePreThread=blockwork.max_nonce+1;
				        }
                if (pblock->nNonce >= 0xffff0000)
                    break;

                // Primecoin: reset sieve+primality round timer
                nPrimeTimerStart = GetTimeMicros();
                if (dTimeExpected > dTimeExpectedPrev)
                    fIncrementPrimorial = !fIncrementPrimorial;

                // Primecoin: primorial always needs to be incremented if only 0 primes were found
                if (nRoundPrimesHit ==0)
                    fIncrementPrimorial = true;

                nRoundTests = 0;
                nRoundPrimesHit = 0;


            }
        }
    } }
    catch (boost::thread_interrupted)
    {
        printf("PrimecoinMiner terminated\n");
        throw;
    }
}
